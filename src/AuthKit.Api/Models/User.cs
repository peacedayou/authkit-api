namespace AuthKit.Api.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Email { get; set; }
    public string PasswordHash { get; set; } = "";
    public string Roles { get; set; } = "User"; // séparés par des virgules
    public int FailedLogins { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public IEnumerable<string> RoleList => Roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public required string TokenHash { get; set; } // seule l'empreinte SHA-256 est stockée
    public Guid FamilyId { get; set; } // chaîne de rotation, pour détecter la réutilisation
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
