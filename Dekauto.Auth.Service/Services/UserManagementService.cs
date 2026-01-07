using Dekauto.Auth.Service.Domain.Entities;
using Dekauto.Auth.Service.Domain.Entities.DTO;
using Dekauto.Auth.Service.Domain.Interfaces;

namespace Dekauto.Auth.Service.Services
{
    public class UserManagementService : IUserManagementService
    {
        private readonly ITokenRepository tokenRepository;
        private readonly IUsersRepository usersRepository;

        public UserManagementService(ITokenRepository tokenRepository, 
            IUsersRepository usersRepository)
        {
            this.tokenRepository = tokenRepository;
            this.usersRepository = usersRepository;
        }

        public async Task<List<UserSessionDto>> GetUserSessionsAsync(string login)
        {
            // Получаем сущности из БД
            Guid userId = Guid.Empty;
            var user = await usersRepository.GetByLoginAsync(login);

            if (user is not null)
                { userId = user.Id; }
            else
                throw new KeyNotFoundException($"Пользователь с логином {login} не найден.");
            
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

        public async Task RevokeAllUserSessionsAsync(string login, string reason)
        {
            Guid userId = Guid.Empty;
            var user = await usersRepository.GetByLoginAsync(login);

            if (user is not null)
                { userId = user.Id; }
            else
                throw new KeyNotFoundException($"Пользователь с логином {login} не найден.");

            await tokenRepository.RevokeAllUserTokensAsync(userId, reason);
        }

        public async Task RevokeAllSessionsAsync(string reason)
        {
            await tokenRepository.RevokeAllTokensAsync(reason);
        }
    }
}
