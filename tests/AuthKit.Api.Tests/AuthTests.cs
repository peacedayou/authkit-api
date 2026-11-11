using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;

namespace AuthKit.Api.Tests;

public class AuthTests : IDisposable
{
    private readonly AuthKitFactory _factory = new();
    private readonly HttpClient _client;
    private const string Password = "Correct-Horse-42";

    public AuthTests() => _client = _factory.CreateClient();

    public void Dispose() => _factory.Dispose();

    private record Tokens(string AccessToken, DateTimeOffset AccessTokenExpiresAt, string RefreshToken);
    private record Me(Guid Id, string Email, string[] Roles);

    private async Task Register(string email = "alice@example.com", string password = Password)
    {
        var r = await _client.PostAsJsonAsync("/auth/register", new { email, password });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
    }

    private async Task<HttpResponseMessage> LoginRaw(string email, string password) =>
        await _client.PostAsJsonAsync("/auth/login", new { email, password });

    private async Task<Tokens> Login(string email = "alice@example.com", string password = Password)
    {
        var r = await LoginRaw(email, password);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<Tokens>())!;
    }

    private async Task<HttpResponseMessage> GetWithToken(string url, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(req);
    }

    [Fact]
    public async Task Register_login_and_read_profile()
    {
        await Register("Alice@Example.com");
        var tokens = await Login("alice@example.com");
        var me = await (await GetWithToken("/me", tokens.AccessToken)).Content.ReadFromJsonAsync<Me>();
        Assert.Equal("alice@example.com", me!.Email);
        Assert.Equal(new[] { "User" }, me.Roles);
    }

    [Theory]
    [InlineData("court1A")]
    [InlineData("toutenminuscules123")]
    [InlineData("SANSCHIFFRESNIMINUS")]
    public async Task Weak_passwords_are_rejected(string password)
    {
        var r = await _client.PostAsJsonAsync("/auth/register", new { email = "bob@example.com", password });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Duplicate_email_is_409()
    {
        await Register();
        var r = await _client.PostAsJsonAsync("/auth/register", new { email = "ALICE@example.com", password = Password });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_give_the_same_answer()
    {
        await Register();
        var wrong = await LoginRaw("alice@example.com", "Mauvais-Passe-99");
        var unknown = await LoginRaw("personne@example.com", Password);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Contains("invalide", await wrong.Content.ReadAsStringAsync());
        Assert.Contains("invalide", await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Account_locks_after_five_failures_then_unlocks()
    {
        await Register();
        for (var i = 0; i < 5; i++) await LoginRaw("alice@example.com", "Mauvais-Passe-99");
        Assert.Equal((HttpStatusCode)423, (await LoginRaw("alice@example.com", Password)).StatusCode);

        _factory.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(HttpStatusCode.OK, (await LoginRaw("alice@example.com", Password)).StatusCode);
    }

    [Fact]
    public async Task Invalid_or_missing_token_is_rejected()
    {
        await Register();
        var tokens = await Login();
        Assert.Equal(HttpStatusCode.OK, (await GetWithToken("/me", tokens.AccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GetWithToken("/me", "pas-un-jeton")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task Refresh_rotates_the_token()
    {
        await Register();
        var first = await Login();
        var r = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = first.RefreshToken });
        var second = (await r.Content.ReadFromJsonAsync<Tokens>())!;
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
    }

    [Fact]
    public async Task Reusing_an_old_refresh_token_revokes_the_whole_session()
    {
        await Register();
        var first = await Login();
        var second = (await (await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = first.RefreshToken }))
            .Content.ReadFromJsonAsync<Tokens>())!;

        // Un voleur rejoue l'ancien jeton
        var replay = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = first.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // Le jeton légitime le plus récent est aussi révoqué
        var legit = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = second.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, legit.StatusCode);
    }

    [Fact]
    public async Task Refresh_token_expires()
    {
        await Register();
        var t = await Login();
        _factory.Clock.Advance(TimeSpan.FromDays(8));
        var r = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = t.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_refresh_token()
    {
        await Register();
        var t = await Login();
        Assert.Equal(HttpStatusCode.NoContent, (await _client.PostAsJsonAsync("/auth/logout", new { refreshToken = t.RefreshToken })).StatusCode);
        var r = await _client.PostAsJsonAsync("/auth/refresh", new { refreshToken = t.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Admin_routes_require_admin_role()
    {
        await Register();
        var user = await Login();
        Assert.Equal(HttpStatusCode.Forbidden, (await GetWithToken("/admin/users", user.AccessToken)).StatusCode);

        var admin = await Login(AuthKitFactory.AdminEmail, AuthKitFactory.AdminPassword);
        var users = await (await GetWithToken("/admin/users", admin.AccessToken)).Content.ReadFromJsonAsync<Me[]>();
        Assert.Equal(2, users!.Length);

        var alice = users.Single(u => u.Email == "alice@example.com");
        var req = new HttpRequestMessage(HttpMethod.Put, $"/admin/users/{alice.Id}/roles")
        {
            Content = JsonContent.Create(new { roles = new[] { "User", "Admin" } })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", admin.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(req)).StatusCode);

        // Le nouveau rôle s'applique au prochain jeton
        var promoted = await Login();
        Assert.Equal(HttpStatusCode.OK, (await GetWithToken("/admin/users", promoted.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task Unknown_role_is_rejected()
    {
        var admin = await Login(AuthKitFactory.AdminEmail, AuthKitFactory.AdminPassword);
        var me = await (await GetWithToken("/me", admin.AccessToken)).Content.ReadFromJsonAsync<Me>();
        var req = new HttpRequestMessage(HttpMethod.Put, $"/admin/users/{me!.Id}/roles")
        {
            Content = JsonContent.Create(new { roles = new[] { "SuperRoot" } })
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", admin.AccessToken);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task Password_is_never_stored_in_clear()
    {
        await Register();
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthKit.Api.Data.AppDbContext>();
        var user = db.Users.Single(u => u.Email == "alice@example.com");
        Assert.DoesNotContain(Password, user.PasswordHash);
        Assert.True(db.RefreshTokens.All(t => t.TokenHash.Length == 64));
    }
}

public class RateLimitTests
{
    [Fact]
    public async Task Too_many_login_attempts_return_429()
    {
        using var factory = new AuthKitFactory(authPerMinute: 3);
        var client = factory.CreateClient();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 4; i++)
            codes.Add((await client.PostAsJsonAsync("/auth/login", new { email = "x@example.com", password = "y" })).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, codes[^1]);
    }
}
