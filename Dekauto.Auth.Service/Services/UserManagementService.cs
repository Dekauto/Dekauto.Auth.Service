using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Interfaces;

namespace Dekauto.Auth.Service.Services
{
    public class UserManagementService : IUserManagementService
    {
        private readonly ITokenRepository tokenRepository;

        public UserManagementService(ITokenRepository tokenRepository)
        {
            this.tokenRepository = tokenRepository;
        }

        public async Task<List<UserSessionDto>> GetUserSessionsAsync(Guid userId)
        {
            // Получаем сущности из БД
            var sessions = await tokenRepository.GetUserSessionsAsync(userId);

            // Маппим в DTO
            return sessions.Select(s => new UserSessionDto
            {
                Jti = s.Jti,
                DeviceInfo = s.DeviceInfo ?? "Unknown", // Если не сохраняли, будет Unknown
                IpAddress = s.IpAddress?.ToString() ?? "Unknown",
                CreatedAt = s.CreatedAt,
                ExpiresAt = s.ExpiresAt,
                IsRevoked = s.IsRevoked,
                RevokeReason = s.RevokeReason
            }).ToList();
        }

        public async Task RevokeSessionAsync(string jti, string reason)
        {
            await tokenRepository.RevokeByJtiAsync(jti, reason);
        }

        public async Task RevokeAllUserSessionsAsync(Guid userId, string reason)
        {
            await tokenRepository.RevokeAllUserTokensAsync(userId, reason);
        }
    }
}
