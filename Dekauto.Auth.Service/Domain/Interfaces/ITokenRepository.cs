using Dekauto.Auth.Service.Domain.Entities;
using System;

namespace Dekauto.Auth.Service.Domain.Interfaces
{
    public interface ITokenRepository
    {
        /// <summary>
        /// Сохраняет информацию о новой паре токенов (access + refresh).
        /// </summary>
        Task SaveTokenInfoAsync(TokenInfo tokenInfo);

        /// <summary>
        /// Ищет активную (не просроченную) запись по хешу Refresh токена.
        /// Используется при попытке обновления (Refresh Token Flow).
        /// </summary>
        Task<TokenInfo?> GetByRefreshTokenHashAsync(string refreshTokenHash);

        /// <summary>
        /// Проверяет, заблокирован ли конкретный Access Token (по его JTI).
        /// Используется в Middleware при каждом запросе.
        /// Возвращает true, если токен отозван или запись не найдена.
        /// </summary>
        Task<bool> IsTokenRevokedAsync(string jti);

        /// <summary>
        /// Отзывает конкретный токен по JTI (например, при выходе пользователя или блокировке сессии админом).
        /// </summary>
        Task RevokeByJtiAsync(string jti, string reason = null);

        /// <summary>
        /// Отзывает все токены пользователя (Logout from all devices).
        /// </summary>
        Task RevokeAllUserTokensAsync(Guid userId, string reason = null);

        /// <summary>
        /// (Опционально) Получение всех сессий пользователя для админки.
        /// </summary>
        Task<List<TokenInfo>> GetUserSessionsAsync(Guid userId);
    }

}
