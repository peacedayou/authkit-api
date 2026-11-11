using System.ComponentModel.DataAnnotations;

namespace AuthKit.Api.Services;

public class JwtOptions
{
    public const string Section = "Jwt";

    [Required, MinLength(32, ErrorMessage = "Jwt:Key doit contenir au moins 32 caractères")]
    public string Key { get; set; } = "";

    public string Issuer { get; set; } = "authkit";
    public string Audience { get; set; } = "authkit-clients";

    [Range(1, 60)]
    public int AccessTokenMinutes { get; set; } = 15;

    [Range(1, 90)]
    public int RefreshTokenDays { get; set; } = 7;
}
