using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using AuthKit.Api.Data;
using AuthKit.Api.Models;
using AuthKit.Api.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthKit.Api.Endpoints;

public static class AuthEndpoints
{
    public const int MaxFailedLogins = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly string[] AllowedRoles = ["User", "Admin"];

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/auth").RequireRateLimiting("auth").WithTags("Authentification");

        auth.MapPost("/register", async (RegisterRequest req, AppDbContext db, IPasswordHasher<User> hasher, TimeProvider clock) =>
        {
            if (!TryValidate(req, out var errors)) return Results.ValidationProblem(errors);
            if (!IsStrong(req.Password))
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["password"] = ["Au moins 12 caractères, avec une majuscule, une minuscule et un chiffre."]
                });

            var email = req.Email.Trim().ToLowerInvariant();
            if (await db.Users.AnyAsync(u => u.Email == email))
                return Results.Conflict(new { title = "Ce courriel est déjà utilisé." });

            var user = new User { Email = email, CreatedAt = clock.GetUtcNow() };
            user.PasswordHash = hasher.HashPassword(user, req.Password);
            db.Users.Add(user);
            await db.SaveChangesAsync();
            return Results.Created($"/me", ToResponse(user));
        });

        auth.MapPost("/login", async (LoginRequest req, AppDbContext db, IPasswordHasher<User> hasher, TokenService tokens,
            TimeProvider clock) =>
        {
            var now = clock.GetUtcNow();
            var email = (req.Email ?? "").Trim().ToLowerInvariant();
            var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);

            // Même message dans tous les cas d'échec : on ne révèle pas si le compte existe
            var invalid = Results.Problem("Courriel ou mot de passe invalide.", statusCode: 401);
            if (user is null)
            {
                hasher.HashPassword(new User { Email = email }, req.Password ?? ""); // temps de réponse constant
                return invalid;
            }
            if (user.LockoutEnd is { } end && end > now)
                return Results.Problem("Compte temporairement verrouillé. Réessayez plus tard.", statusCode: 423);

            var check = hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password ?? "");
            if (check == PasswordVerificationResult.Failed)
            {
                user.FailedLogins++;
                if (user.FailedLogins >= MaxFailedLogins)
                {
                    user.LockoutEnd = now.Add(LockoutDuration);
                    user.FailedLogins = 0;
                }
                await db.SaveChangesAsync();
                return invalid;
            }
            if (check == PasswordVerificationResult.SuccessRehashNeeded)
                user.PasswordHash = hasher.HashPassword(user, req.Password!);

            user.FailedLogins = 0;
            user.LockoutEnd = null;
            return Results.Ok(await IssueAsync(db, tokens, user, Guid.NewGuid()));
        });

        auth.MapPost("/refresh", async (RefreshRequest req, AppDbContext db, TokenService tokens, TimeProvider clock) =>
        {
            var now = clock.GetUtcNow();
            var hash = TokenService.Hash(req.RefreshToken ?? "");
            var stored = await db.RefreshTokens.Include(t => t.User).SingleOrDefaultAsync(t => t.TokenHash == hash);
            if (stored is null || stored.User is null) return Results.Problem("Jeton invalide.", statusCode: 401);

            if (stored.RevokedAt is not null)
            {
                // Un jeton déjà utilisé revient : il a probablement été volé. On révoque toute la chaîne.
                await db.RefreshTokens
                    .Where(t => t.FamilyId == stored.FamilyId && t.RevokedAt == null)
                    .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now));
                return Results.Problem("Jeton réutilisé : session révoquée par sécurité.", statusCode: 401);
            }
            if (stored.ExpiresAt <= now) return Results.Problem("Jeton expiré.", statusCode: 401);

            stored.RevokedAt = now;
            return Results.Ok(await IssueAsync(db, tokens, stored.User, stored.FamilyId));
        });

        auth.MapPost("/logout", async (RefreshRequest req, AppDbContext db, TimeProvider clock) =>
        {
            var hash = TokenService.Hash(req.RefreshToken ?? "");
            var stored = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
            if (stored is not null && stored.RevokedAt is null)
            {
                await db.RefreshTokens
                    .Where(t => t.FamilyId == stored.FamilyId && t.RevokedAt == null)
                    .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, clock.GetUtcNow()));
            }
            return Results.NoContent(); // même réponse si le jeton est inconnu
        });

        app.MapGet("/me", async (ClaimsPrincipal principal, AppDbContext db) =>
        {
            var id = Guid.Parse(principal.FindFirstValue("sub")!);
            var user = await db.Users.FindAsync(id);
            return user is null ? Results.NotFound() : Results.Ok(ToResponse(user));
        }).RequireAuthorization().WithTags("Profil");

        var admin = app.MapGroup("/admin").RequireAuthorization(p => p.RequireRole("Admin")).WithTags("Administration");

        admin.MapGet("/users", async (AppDbContext db) =>
            (await db.Users.OrderBy(u => u.Email).ToListAsync()).Select(ToResponse));

        admin.MapPut("/users/{id:guid}/roles", async (Guid id, RolesRequest req, AppDbContext db) =>
        {
            var roles = req.Roles.Select(r => r.Trim()).Distinct().ToArray();
            if (roles.Length == 0 || roles.Any(r => !AllowedRoles.Contains(r)))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["roles"] = [$"Rôles permis : {string.Join(", ", AllowedRoles)}"] });
            var user = await db.Users.FindAsync(id);
            if (user is null) return Results.NotFound();
            user.Roles = string.Join(",", roles);
            await db.SaveChangesAsync();
            return Results.Ok(ToResponse(user));
        });
    }

    private static async Task<TokenResponse> IssueAsync(AppDbContext db, TokenService tokens, User user, Guid familyId)
    {
        var (access, expires) = tokens.CreateAccessToken(user);
        var refresh = TokenService.NewRefreshToken();
        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = TokenService.Hash(refresh),
            FamilyId = familyId,
            ExpiresAt = tokens.RefreshExpiry(),
        });
        await db.SaveChangesAsync();
        return new TokenResponse(access, expires, refresh);
    }

    private static UserResponse ToResponse(User u) => new(u.Id, u.Email, u.RoleList, u.CreatedAt);

    public static bool IsStrong(string password) =>
        password.Length >= 12 && password.Any(char.IsUpper) && password.Any(char.IsLower) && password.Any(char.IsDigit);

    private static bool TryValidate(object model, out Dictionary<string, string[]> errors)
    {
        var results = new List<ValidationResult>();
        var ok = Validator.TryValidateObject(model, new ValidationContext(model), results, validateAllProperties: true);
        errors = results
            .SelectMany(r => r.MemberNames.DefaultIfEmpty("").Select(m => (Member: m, r.ErrorMessage)))
            .GroupBy(x => x.Member.ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.Select(x => x.ErrorMessage ?? "Invalide").ToArray());
        return ok;
    }
}
