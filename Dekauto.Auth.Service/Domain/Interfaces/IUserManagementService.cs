using Dekauto.Auth.Service.Domain.Entities.DTO;

namespace Dekauto.Auth.Service.Domain.Interfaces
{
    public interface IUserManagementService
    {
        /// <summary>
        /// Получает список всех сессий пользователя (активных и отозванных).
        /// </summary>
        Task<List<UserSessionDto>> GetUserSessionsAsync(Guid userId);

        /// <summary>
        /// Отзывает (блокирует) конкретную сессию по её JTI.
        /// </summary>
        Task RevokeSessionAsync(string jti, string reason);

        /// <summary>
        /// Отзывает (блокирует) вообще все сессии пользователя.
        /// </summary>
        Task RevokeAllUserSessionsAsync(Guid userId, string reason);
    }
}
