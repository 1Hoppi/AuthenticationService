public interface IHasher
{
    public (byte[], byte[]) HashPassword(string password);
    public (byte[], byte[]) HashPassword(string password, byte[] salt);
    public bool VerifyPassword(string password, byte[] storedHash, byte[] saltBytes);
}
