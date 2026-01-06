namespace Dekauto.Auth.Service.Domain.Entities.DTO
{
    public class RefreshTokenDto
    {
        public string Token { get; set; }
        public Guid UserId { get; set; }
        public DateTime? Expires { get; set; }
    }
}
