using System.ComponentModel.DataAnnotations;

namespace AuthKit.Api.Endpoints;

public record RegisterRequest(
    [property: Required, EmailAddress, MaxLength(254)] string Email,
    [property: Required, MinLength(12), MaxLength(128)] string Password);

public record LoginRequest([property: Required] string Email, [property: Required] string Password);

public record RefreshRequest([property: Required] string RefreshToken);

public record TokenResponse(string AccessToken, DateTimeOffset AccessTokenExpiresAt, string RefreshToken, string TokenType = "Bearer");

public record UserResponse(Guid Id, string Email, IEnumerable<string> Roles, DateTimeOffset CreatedAt);

public record RolesRequest([property: Required] string[] Roles);
