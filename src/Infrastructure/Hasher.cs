using System.Security.Cryptography;
using Microsoft.Extensions.Options;

public class Hasher : IHasher
{
    private readonly string _pepper;
    private const int SaltBytes = 16;

    public Hasher(IOptions<SecuritySettings> options)
    {
        _pepper = options.Value.Pepper;
    }

    public (byte[], byte[]) HashPassword(string password)
    {
        byte[] salt = new byte[SaltBytes];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        return this.HashPassword(password, salt);
    }

    public (byte[], byte[]) HashPassword(string password, byte[] salt)
    {
        string pepperedPassword = password + _pepper;

        byte[] hash;
        using (var pbkdf2 = new Rfc2898DeriveBytes(
            pepperedPassword,
            salt,
            100_000,
            HashAlgorithmName.SHA256))
        {
            hash = pbkdf2.GetBytes(32);
        }

        return (hash, salt);
    }

    public bool VerifyPassword(string password, byte[] storedHash, byte[] saltBytes)
    {
        string pepperedPassword = password + _pepper;
        byte[] computedHash;
        using (var pbkdf2 = new Rfc2898DeriveBytes(
            pepperedPassword,
            saltBytes,
            100_000,
            HashAlgorithmName.SHA256))
        {
            computedHash = pbkdf2.GetBytes(32);
        }

        return CryptographicOperations.FixedTimeEquals(storedHash, computedHash);
    }
}
