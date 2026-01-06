using Dekauto.Auth.Service.Domain.Entities;
using System;

namespace Dekauto.Auth.Service.Domain.Interfaces
{
    public interface ITokenRepository
    {
        Task<RefreshToken> GetRefreshTokenAsync(string token);
        Task AddRefreshTokenAsync(RefreshToken refreshToken);
        Task UpdateRefreshTokenAsync(RefreshToken refreshToken);
        Task RevokeRefreshTokenAsync(string token, string reason = null);
        Task RevokeAllUserTokensAsync(Guid userId, string reason = null);
        Task<List<RefreshToken>> GetUserTokensAsync(Guid userId);

        // Для TokenInfo (JTI блокировка)
        Task AddTokenInfoAsync(TokenInfo tokenInfo);
        Task<TokenInfo> GetTokenInfoAsync(string jti);
        Task RevokeTokenByJtiAsync(string jti, string reason = null);
        Task<bool> IsTokenRevokedAsync(string jti);
    }
}
