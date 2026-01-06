namespace Dekauto.Auth.Service.Domain.Entities
{
    public class RefreshToken
    {
        public string Token { get; set; }
        public Guid UserId { get; set; }
        public string JwtId { get; set; } // Связь с JTI из access token
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string RevokeReason { get; set; }

        public virtual User User { get; set; }
    }


}
