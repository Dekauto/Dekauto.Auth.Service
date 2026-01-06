using Dekauto.Auth.Service.Domain.Entities;
using Dekauto.Auth.Service.Domain.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Dekauto.Auth.Service.Infrastructure.Repositories
{
    public class TokenRepository : ITokenRepository
    {
        private readonly DekautoContext context;

        public TokenRepository(DekautoContext context)
        {
            this.context = context;
        }

        public async Task SaveTokenInfoAsync(TokenInfo tokenInfo)
        {
            if (tokenInfo == null) throw new ArgumentNullException(nameof(tokenInfo));

            await context.TokenInfos.AddAsync(tokenInfo);
            await context.SaveChangesAsync();
        }

        public async Task<TokenInfo?> GetByRefreshTokenHashAsync(string refreshTokenHash)
        {
            if (string.IsNullOrEmpty(refreshTokenHash)) return null;

            // Ищем токен, который соответствует хешу и срок действия которого еще не истек.
            // Статус IsRevoked мы проверим уже в бизнес-логике, чтобы вернуть точную ошибку,
            // но можно отфильтровать и здесь.
            return await context.TokenInfos
                .Include(t => t.User) // Подгружаем юзера, так как он нужен для генерации новых клеймов
                .FirstOrDefaultAsync(t => t.RefreshTokenHash == refreshTokenHash
                                          && t.ExpiresAt > DateTime.UtcNow);
        }

        public async Task<bool> IsTokenRevokedAsync(string jti)
        {
            if (string.IsNullOrEmpty(jti)) return true;

            // Ищем запись. Если записи нет - считаем токен невалидным (true).
            // Если запись есть, возвращаем значение флага IsRevoked.
            var tokenInfo = await context.TokenInfos
                .Select(t => new { t.Jti, t.IsRevoked }) // Выбираем только нужные поля для скорости
                .FirstOrDefaultAsync(t => t.Jti == jti);

            if (tokenInfo == null)
            {
                // Если токен не найден в БД (например, удален очисткой), считаем его отозванным
                return true;
            }

            return tokenInfo.IsRevoked;
        }

        public async Task RevokeByJtiAsync(string jti, string reason = null)
        {
            if (string.IsNullOrEmpty(jti)) return;

            // Используем ExecuteUpdate для производительности (без выгрузки объекта в память)
            await context.TokenInfos
                .Where(t => t.Jti == jti)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.RevokedAt, DateTime.UtcNow)
                    .SetProperty(t => t.RevokeReason, reason ?? "Revoked by JTI"));
        }

        public async Task RevokeAllUserTokensAsync(Guid userId, string reason = null)
        {
            // Блокируем все активные (не отозванные) токены пользователя
            await context.TokenInfos
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.IsRevoked, true)
                    .SetProperty(t => t.RevokedAt, DateTime.UtcNow)
                    .SetProperty(t => t.RevokeReason, reason ?? "Revoked all user tokens"));
        }

        public async Task<List<TokenInfo>> GetUserSessionsAsync(Guid userId)
        {
            // Возвращаем список сессий, отсортированный по дате создания (новые сверху)
            return await context.TokenInfos
                .AsNoTracking() // Read-only запрос
                .Where(t => t.UserId == userId)
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();
        }
    }
}