using System;
using System.Collections.Generic;
using System.Net;

namespace Dekauto.Auth.Service.Domain.Entities;

public partial class TokenInfo
{
    public Guid Id { get; set; }

    public string Jti { get; set; } = null!;

    public string RefreshTokenHash { get; set; } = null!;

    public Guid UserId { get; set; }

    public DateTime ExpiresAt { get; set; }

    public DateTime CreatedAt { get; set; }

    public bool IsRevoked { get; set; }

    public DateTime? RevokedAt { get; set; }

    public string? RevokeReason { get; set; }

    public string? DeviceInfo { get; set; }

    public IPAddress? IpAddress { get; set; }

    public virtual User User { get; set; } = null!;
}
