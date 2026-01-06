using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.AspNetCore.Authorization;
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
            // 1. Проверяем, является ли эндпоинт анонимным (Login, Register и т.д.)
            var endpoint = context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
            {
                // Если доступ разрешен всем, не проверяем токен, даже если он прислан
                await _next(context);
                return;
            }

            // 2. Стандартная проверка
            if (context.User.Identity != null && context.User.Identity.IsAuthenticated)
            {
                var jti = context.User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

                if (!string.IsNullOrEmpty(jti))
                {
                    if (await tokenRepository.IsTokenRevokedAsync(jti))
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        // Можно не писать тело ответа, чтобы не ломать JSON парсеры на фронте, 
                        // или вернуть стандартный ProblemDetails
                        return;
                    }
                }
            }

            await _next(context);
        }
    }

}