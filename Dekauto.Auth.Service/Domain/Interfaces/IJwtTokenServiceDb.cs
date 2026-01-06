using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Entities.Models;
using System.Security.Claims;

namespace Dekauto.Auth.Service.Domain.Interfaces
{
    public interface IJwtTokenServiceDb
    {
        // Метод стал асинхронным, так как сохраняет данные в БД
        Task<TokensModel> GenerateTokensAsync(UserDto account);

        // Метод проверки и обновления
        Task<TryRefreshTokensModel> TryRefreshTokensAsync(string refreshToken, UserDto userDto);

        // Валидация Access токена остается синхронной (CPU-bound проверка подписи)
        // Проверка через БД вынесена в Middleware, здесь только криптография.
        ClaimsPrincipal? ValidateAccessToken(string token);
    }
}
