namespace Dekauto.Auth.Service.Domain.Entities.DTO
{
    public class UserSessionDto
    {
        public string Jti { get; set; }        // ID сессии
        public string DeviceInfo { get; set; } // Браузер/ОС
        public string IpAddress { get; set; }  // IP адрес
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsRevoked { get; set; }    // Статус: отозван или нет
        public string? RevokeReason { get; set; }
    }
}
