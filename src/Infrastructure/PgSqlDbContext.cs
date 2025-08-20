using Microsoft.EntityFrameworkCore;

public class PgSqlDbContext : DbContext
{
    public PgSqlDbContext(DbContextOptions<PgSqlDbContext> options)
        : base(options) { }

    public DbSet<UserCredentials> UserCredentials { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserCredentials>();
    }
}
