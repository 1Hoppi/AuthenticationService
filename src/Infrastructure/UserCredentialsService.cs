using Grpc.Core;
using Microsoft.EntityFrameworkCore;

public class UserCredentialsService : IUserCredentialsService
{
    private readonly PgSqlDbContext _pgSqlDbContext;

    public UserCredentialsService(PgSqlDbContext pgSqlDbContext)
    {
        _pgSqlDbContext = pgSqlDbContext;
    }

    public async Task<bool> GetUsernameAvailability(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty");

        bool exists = await _pgSqlDbContext.UserCredentials.AnyAsync(u => u.Username == username);

        return !exists;
    }

    public async Task<int> CreateNewUser(Guid userId, string username, byte[] passwordHash, byte[] passwordSalt)
    {
        UserCredentials user = new UserCredentials
        {
            UserId = userId,
            Username = username,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt
        };

        _pgSqlDbContext.UserCredentials.Add(user);

        int affectedRows = await _pgSqlDbContext.SaveChangesAsync();

        return affectedRows;
    }

    public async Task<UserCredentials?> GetCredentialsByUsernameAsync(string username)
    {
        var credential = await _pgSqlDbContext.UserCredentials
            .FirstOrDefaultAsync(u => u.Username == username);

        return credential;
    }
}
