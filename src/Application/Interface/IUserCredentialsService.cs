public interface IUserCredentialsService
{
    public Task<bool> GetUsernameAvailability(string username);
    public Task<int> CreateNewUser(Guid userId, string username, byte[] passwordHash, byte[] passwordSalt);
    public Task<UserCredentials?> GetCredentialsByUsernameAsync(string username);
}