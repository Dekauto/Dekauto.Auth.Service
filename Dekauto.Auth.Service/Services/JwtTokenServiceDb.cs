using Dekauto.Auth.Service.Domain.Entities;
using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Entities.Models;
using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Dekauto.Auth.Service.Services
{
    public class JwtTokenServiceDb : IJwtTokenServiceDb
    {
        private readonly IConfiguration configuration;
        private readonly ITokenRepository tokenRepository;

        public JwtTokenServiceDb(IConfiguration configuration, ITokenRepository tokenRepository)
        {
            this.configuration = configuration;
            this.tokenRepository = tokenRepository;
        }

        // Публичный метод выдачи токенов (Login Flow)
        public async Task<TokensModel> GenerateTokensAsync(UserDto account)
        {
            if (account is null)
            {
                throw new ArgumentNullException(nameof(account));
            }

            // 1. Генерируем уникальный ID для этой пары токенов (JTI)
            var jti = Guid.NewGuid().ToString();

            // 2. Создаем Access Token (включая JTI в claims)
            var accessToken = GenerateAccessToken(account, jti);

            // 3. Создаем Refresh Token (Raw строка для клиента + Хеш для БД)
            var (refreshTokenRaw, refreshTokenHash, expiresAt) = GenerateRefreshTokenData();

            // 4. Сохраняем информацию о сессии в БД
            var tokenInfo = new TokenInfo
            {
                Jti = jti,
                UserId = account.Id,
                RefreshTokenHash = refreshTokenHash,
                ExpiresAt = expiresAt,
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false,
                // IpAddress и DeviceInfo можно прокинуть сюда, если расширить сигнатуру метода
            };

            await tokenRepository.SaveTokenInfoAsync(tokenInfo);

            // 5. Формируем ответ
            var tokensAdapter = new AccessTokenDto(accessToken, account);

            // Используем старую сущность RefreshToken как DTO для совместимости с TokensModel
            // Но в БД она больше не идет.
            var refreshTokenDto = new RefreshToken
            {
                Token = refreshTokenRaw, // Отдаем пользователю чистый токен
                UserId = account.Id,
                JwtId = jti,
                ExpiresAt = expiresAt
            };

            return new TokensModel(tokensAdapter, refreshTokenDto);
        }

        // Метод проверки rt и выдачи новых (Refresh Token Rotation Flow)
        public async Task<TryRefreshTokensModel> TryRefreshTokensAsync(string refreshTokenRaw, UserDto userDto)
        {
            if (string.IsNullOrEmpty(refreshTokenRaw))
            {
                throw new ArgumentException($"'{nameof(refreshTokenRaw)}' cannot be null or empty.", nameof(refreshTokenRaw));
            }

            if (userDto is null)
            {
                throw new ArgumentNullException(nameof(userDto));
            }

            // 1. Хешируем полученный токен, чтобы найти его в БД
            var refreshTokenHash = ComputeSha256Hash(refreshTokenRaw);

            // 2. Ищем токен в БД
            var existingToken = await tokenRepository.GetByRefreshTokenHashAsync(refreshTokenHash);

            // 3. Проверки валидности
            if (existingToken == null)
            {
                // Токен не найден или истек (фильтруется в репозитории)
                return new TryRefreshTokensModel(false, null);
            }

            if (existingToken.IsRevoked)
            {
                // CRITICAL SECURITY: Попытка использования уже отозванного токена!
                // Это может означать кражу токенов. 
                // В идеале здесь можно заблокировать ВСЕ сессии пользователя (RevokeAllUserTokensAsync).
                // Пока просто отказываем.
                return new TryRefreshTokensModel(false, null);
            }

            if (existingToken.UserId != userDto.Id)
            {
                // Попытка обновить токен чужого пользователя
                return new TryRefreshTokensModel(false, null);
            }

            // 4. ROTATION: Отзываем старый токен (он был использован только что)
            // Мы не удаляем его, а помечаем как использованный/отозванный, чтобы предотвратить повторное использование (Replay Attack)
            await tokenRepository.RevokeByJtiAsync(existingToken.Jti, "Refresh Token Rotation");

            // 5. Генерируем новую пару токенов
            var newTokens = await GenerateTokensAsync(userDto);

            return new TryRefreshTokensModel(true, newTokens);
        }

        // Внутренний метод генерации access токена
        private string GenerateAccessToken(UserDto account, string jti)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, account.Login),
                new Claim(JwtRegisteredClaimNames.Jti, jti), // ВАЖНО: JTI теперь приходит снаружи
                new Claim(ClaimTypes.NameIdentifier, account.Id.ToString()),
                new Claim(ClaimTypes.Role, account.EngRoleName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(configuration["Jwt:ExpireMinutes"]));

            var token = new JwtSecurityToken(
                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Внутренний метод генерации данных для Refresh Token
        private (string rawToken, string hashedToken, DateTime expiresAt) GenerateRefreshTokenData()
        {
            // Генерируем случайную строку (32 байта -> Base64)
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            var rawToken = Convert.ToBase64String(randomNumber);

            // Хешируем для БД
            var hashedToken = ComputeSha256Hash(rawToken);

            // Срок действия
            var refreshTokenPeriod = configuration["Jwt:RefreshTokenPeriod"] ?? "d";
            var expiresAt = refreshTokenPeriod == "d"
                ? DateTime.UtcNow.AddDays(Convert.ToDouble(configuration["Jwt:RefreshTokenExpireDays"] ?? "7"))
                : DateTime.UtcNow.AddMinutes(Convert.ToDouble(configuration["Jwt:RefreshTokenExpireMinutes"] ?? "60"));

            return (rawToken, hashedToken, expiresAt);
        }

        // Хелпер для хеширования
        private static string ComputeSha256Hash(string input)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(bytes);
        }

        // Метод валидации Access токена (только криптография)
        public ClaimsPrincipal? ValidateAccessToken(string token)
        {
            if (string.IsNullOrEmpty(token)) return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"]);
                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = configuration["Jwt:Audience"],
                    ValidateLifetime = true, // Проверяем срок действия (exp)
                    ClockSkew = TimeSpan.Zero
                }, out _);

                return principal;
            }
            catch
            {
                return null;
            }
        }
    }
}
