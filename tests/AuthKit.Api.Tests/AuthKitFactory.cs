using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace AuthKit.Api.Tests;

public class AuthKitFactory(int authPerMinute = 1000) : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@authkit.test";
    public const string AdminPassword = "Admin-Password-2026";

    private readonly string _db = Path.Combine(Path.GetTempPath(), $"authkit-{Guid.NewGuid()}.db");
    // Démarre à l'heure réelle : la validation des jetons JWT utilise l'horloge du système
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ConnectionStrings:Default", $"Data Source={_db};Pooling=False");
        builder.UseSetting("Jwt:Key", "cle-de-test-tres-longue-et-aleatoire-0123456789");
        builder.UseSetting("RateLimit:AuthPerMinute", authPerMinute.ToString());
        builder.UseSetting("Admin:Email", AdminEmail);
        builder.UseSetting("Admin:Password", AdminPassword);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (File.Exists(_db)) File.Delete(_db);
    }
}
