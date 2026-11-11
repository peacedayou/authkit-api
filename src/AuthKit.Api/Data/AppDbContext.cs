using AuthKit.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthKit.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(u =>
        {
            u.HasIndex(x => x.Email).IsUnique();
            u.Property(x => x.Email).HasMaxLength(254);
            u.Ignore(x => x.RoleList);
        });
        b.Entity<RefreshToken>(t =>
        {
            t.HasIndex(x => x.TokenHash).IsUnique();
            t.HasIndex(x => x.FamilyId);
            t.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
