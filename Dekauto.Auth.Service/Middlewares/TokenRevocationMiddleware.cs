using Dekauto.Auth.Service.Domain.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;

namespace Dekauto.Auth.Service.Middlewares
{
    public class TokenRevocationMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenRevocationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ITokenRepository tokenRepository)
        {
            // Проверяем, аутентифицирован ли пользователь стандартными средствами (JwtBearer)
            if (context.User.Identity != null && context.User.Identity.IsAuthenticated)
            {
                // Извлекаем JTI из клеймов
                var jti = context.User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

                // Если JTI есть, проверяем его статус в БД
                if (!string.IsNullOrEmpty(jti))
                {
                    // Если токен отозван или не найден (IsRevokedAsync возвращает true в этих случаях)
                    if (await tokenRepository.IsTokenRevokedAsync(jti))
                    {
                        // Принудительно разлогиниваем для текущего запроса
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;

                        // Можно добавить заголовок, чтобы фронт понял причину
                        context.Response.Headers.Append("Token-Revoked", "true");

                        await context.Response.WriteAsync("Token is revoked or invalid.");
                        return; // Прерываем конвейер, не пускаем в контроллер
                    }
                }
            }

            await _next(context);
        }
    }
}