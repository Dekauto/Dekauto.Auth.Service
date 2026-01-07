using Dekauto.Auth.Service.Domain.Interfaces;
using Dekauto.Auth.Service.Infrastructure;
using Dekauto.Auth.Service.Infrastructure.Repositories;
using Dekauto.Auth.Service.Middlewares;
using Dekauto.Auth.Service.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Prometheus;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.Loki;
using System.Reflection;
using System.Text;
using System.Text.Json.Serialization;

var tempOutputTemplate = "[AUTH STARTUP LOGGER] {Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}";
// Временные логгер Serilog для этапа до создания билдера
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Fatal) // Только критические ошибки из Microsoft-сервисов
    .Enrich.FromLogContext()
    .WriteTo.Console(
        outputTemplate: tempOutputTemplate,
        restrictedToMinimumLevel: LogEventLevel.Information
    )
    .WriteTo.File(
        "logs/Auth-startup-log.txt",
        outputTemplate: tempOutputTemplate,
        rollingInterval: RollingInterval.Day,
        restrictedToMinimumLevel: LogEventLevel.Warning
    )
    .WriteTo.Loki(new LokiSinkConfigurations()
    {
        Url = new Uri("http://loki:3100"),
        Labels =
        [
            new LokiLabel("service_name", "dekauto_students"),
            new LokiLabel("app","dekauto_full")
        ]
    })
    .CreateBootstrapLogger(); // временный логгер

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Применение конфигов.
    builder.Configuration
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
        .AddJsonFile($"appsettings.{Environment.UserName.ToLowerInvariant()}.json", optional: true, reloadOnChange: true)
        .AddEnvironmentVariables()
        .AddCommandLine(args);

    // Полноценная настройка Serilog логгера (из конфига)
    builder.Host.UseSerilog((builderContext, serilogConfig) =>
        {
            serilogConfig
                .ReadFrom.Configuration(builderContext.Configuration)
                // Ручная настройка Loki
                .WriteTo.Loki(new LokiSinkConfigurations()
                {
                    Url = new Uri("http://loki:3100"),
                    Labels =
                    [
                        new LokiLabel("service_name", "dekauto_auth"),
                        new LokiLabel("app","dekauto_full"),
                        new LokiLabel("env",
                            builderContext.HostingEnvironment.IsDevelopment() ? "dev" : "prod")
                    ]
                });
        });

    builder.Configuration["Jwt:Key"] = Environment.GetEnvironmentVariable("Jwt__Key");
    var jwtKey = builder.Configuration["Jwt:Key"];
    if (string.IsNullOrEmpty(jwtKey) || jwtKey.Length < 32)
    {
        var mes = "Invalid secret key for JWT tokens - needs to be at least 32 characters long.";
        Log.Fatal(mes);
        throw new InvalidOperationException(mes);
    }

    var connectionString = builder.Configuration.GetConnectionString("Main");

    // Получаем список origins из конфигурации
    var allowedOrigins = builder.Configuration
        .GetSection("CorsSettings:AllowedOrigins").Get<string[]>();

    if (allowedOrigins == null || !allowedOrigins.Any())
    {
        var mes =
            "CORS AllowedOrigins are not specified in serilogConfig (appsettings.json or environment). Can't configure CORS";
        Log.Error(mes);
        throw new InvalidOperationException(mes);
    }
    var useEndpointAuth = Boolean.Parse(builder.Configuration["UseEndpointAuth"] ?? "true");

    if (useEndpointAuth)
    {

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                ValidAudience = builder.Configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
                ClockSkew = TimeSpan.Zero
            };
        });

    // Политики доступа к эндпоинтам
    builder.Services.AddAuthorizationBuilder()
        .AddPolicy("OnlyAdmin", policy => policy.RequireRole("Admin"));

        builder.Services.AddAuthorization();
    }
    else
    {
        // Заглушка политик доступа, если авторизация выключена
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("OnlyAdmin", policy => policy.RequireAssertion(_ => true));
    }

    // Add services to the container.
    builder.Services.AddControllers()
        .AddJsonOptions(options =>
            options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    // Добавление swagger с авторизацией
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Version = "v1",
            Title = "Dekauto Authorization Service API",
            Description = @"## API для управления пользователями и их сессиями. **Требует прав администратора.** 
## Для получения прав администратора, необходимо:
1. Развернуть раздел `UserAuthController`, чтобы были видны цветные эндпоинты.
2. Развернуть эндпоинт `/api/auth`, нажать справа кнопку `Try it out`.
3. В открывшемся поле с текстом, заменить текст в кавычках после login и password на логин и пароль от администраторского аккаунта соответственно (по умолчанию указаны `string`).
4. Нажать синюю кнопку `Execute` ниже и подождать выполнения входа.
5. После окончания загрузки, ниже, в поле `Response body` полностью **выделить** длинное значение `access_token` *(**Важно**: выделять нужно без кавычек)* и **скопировать** его.
6. Справа снизу под этой документацией нажать кнопку `Authorize`, в поле вставить скопированное значение и нажать зеленую кнопку `Authorize`, после чего закрыть окно.
7. Теперь Вы авторизованы для проверки доступа к нужному функционалу.
<br>*(Опционально)* Для проверки текущего аккаунта, так же нажмите на `Execute` на эндпоинте `/api/auth/validate` - будет выведена информация о текущем аккаунте и его роли.
<br>
## Альтернативный путь:
**Внимание:** этот путь описывает отключение обязательного требования авторизации запросов на всем сервисе авторизации в целом, что является **серьезным риском безопасности**.

За включение/отключение авторизации эндпоинтов отвечает переменная `AUTH_ENDPOINT_PROTECTION` в .env конфигурации сервиса, принимающая `true`(вкл) или `false`(выкл).

Для изменения значения переменной необходимо:
1. Открыть `.env` файл, хранящийся на целевом сервере проекта.
2. Изменить значение переменной `AUTH_ENDPOINT_PROTECTION` на `false`.
3. Перезапустить сервис через `docker compose restart dekauto.auth`.
4. Обновить страницу с этой документацией.
После этих шагов пропадет кнопка `Authorize` вместе с значками замков на эндпоинтах - **защита снята и авторизация не требуется**.

***⚠️ После завершения тех. работ не забудьте включить защиту сервиса!***

## Принудительная смена пароля:
Если подобрать пароль от уч. записи администратора не представляется возможным, то его можно принудительно изменить, не отключая защиту сервиса.

Для изменения значения переменной необходимо:
1. Открыть `.env` файл, хранящийся на целевом сервере проекта.
2. Изменить значение переменной `AUTH_FORCE_PASS_CHANGE` на `true`.
3. Перезапустить сервис через `docker compose restart dekauto.auth`.
4. Обновить страницу с этой документацией.
5. Пролистать вниз до раздела `UserManagement` и развернуть его.
6. Выполнить запрос на эндпоинт `/api/users/changepass/force/available` - если в 'Response body' указано `true`, значит функционал доступен.
7. Выполнить запрос на эндпоинт `/api/users/{userId}/changepass/force`, введя в поля логин аккаунта и новый пароль.
8. Проверить, что ответ в 'Response body' `Пароль для пользователя {login} был принудительно изменен.`
Теперь вход в систему для этого пользователя будет осуществляться по новому паролю

***⚠️ После завершения тех. работ не забудьте выключить принудительную смену пароля! Она не защищена и является самым уязвимым местом системы!***"

        });

        // Включаем XML-комментарии для отображения документации в UI
        var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
        c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

        if (useEndpointAuth)
        {
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "Input JWT token (without 'Bearer')",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "Bearer",
                BearerFormat = "JWT"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
        });
        }
    });
    // Добавляем JWT сервис (работающий с БД)
    builder.Services.AddScoped<IJwtTokenServiceDb, JwtTokenServiceDb>();
    builder.Services.AddScoped<ITokenRepository, TokenRepository>();
    builder.Services.AddScoped<IUserManagementService, UserManagementService>();
    builder.Services.AddScoped<IUserAuthServiceDb, UserAuthServiceDb>();
    builder.Services.AddTransient<IUsersRepository, UsersRepository>();
    builder.Services.AddTransient<IRolesRepository, RolesRepository>();
    builder.Services.AddTransient<IRolesService, RolesService>();
    builder.Services.AddSingleton<IRequestMetricsService, RequestMetricsService>();
    builder.Services.AddDbContext<DekautoContext>(options =>
        options.UseNpgsql(connectionString)
        .UseLazyLoadingProxies());
    builder.Services.AddCors(options => options.AddPolicy("AllowMainHosts", policy =>
    {
        policy.WithOrigins(allowedOrigins)
                 .AllowAnyHeader()
                 .AllowAnyMethod()
                 .WithExposedHeaders("Content-Disposition")
                 .AllowCredentials();
    }));


    Log.Information("Building the application...");
    var app = builder.Build();

    // Configure the HTTP request pipeline.


    // Явно указываем порты (для Docker)
    app.Urls.Add("http://*:5507");
    
    app.UseCors("AllowMainHosts");

    if (app.Environment.IsDevelopment())
    {
        Log.Warning("Development version of the application is started. Swagger activation...");
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    // Используем https, если это указано в конфиге
    if (Boolean.Parse(app.Configuration["UseHttps"] ?? "false"))
    {
        app.Urls.Add("https://*:5508");
        app.UseHttpsRedirection();
        Log.Information("Enabled HTTPS.");
    }
    else
    {
        Log.Warning("Disabled HTTPS.");
    }

    if (useEndpointAuth)
    {
        // Аутентификация (JWT, куки)
        app.UseAuthentication();

        // СРАЗУ ПОСЛЕ - проверяем блокировку токена в БД
        app.UseMiddleware<TokenRevocationMiddleware>();

        // Авторизация (проверка атрибутов [Authorize])
        app.UseAuthorization();
    }   
    else
    {
        Log.Warning("Disabled all endpoint authorization.");
    }
    app.MapControllers();

    app.MapMetrics();
    app.UseMetricsMiddleware(); // Метрики

    Log.Information("Application startup...");
    app.Run();
}
catch (Exception ex)
{
    // В случае краха приложения при запуске пытаемся отправить логи:
    // 1. Запись в файл и консоль контейнера
    Log.Fatal(ex, "An unexpected Fatal error has occurred in the application.");
    try
    {
        // 2. Попытка отправить критическую ошибку в Loki
        using var tempLogger = new LoggerConfiguration()
            .WriteTo.Loki(new LokiSinkConfigurations()
            {
                Url = new Uri("http://loki:3100"),
                Labels =
                    [
                        new LokiLabel("service_name", "dekauto_auth"),
                        new LokiLabel("app","dekauto_full")
                    ]
            })
            .CreateLogger();
        tempLogger.Fatal(ex, "[AUTH FATAL TEMPORARY LOGGER] Application startup failed");
    }
    catch (Exception lokiEx)
    {
        Log.Warning(lokiEx, "Failed to send log to Loki");
    }
}
finally
{
    Log.CloseAndFlush();
}