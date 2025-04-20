public sealed class JwtKeyGenerationUserData
{
    public string UserId { get; }
    public string IpAddress { get; }
    public DateTime ExpiresAt { get; }

    private JwtKeyGenerationUserData(string userId, string ipAddress, DateTime expiresAt)
    {
        UserId = userId;
        IpAddress = ipAddress;
        ExpiresAt = expiresAt;
    }

    public static JwtKeyGenerationUserData CreateForAccessToken(string userId, string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new Exception("User ID cannot be empty");

        if (string.IsNullOrWhiteSpace(ipAddress))
            throw new Exception("IP address cannot be empty");

        return new JwtKeyGenerationUserData(
            userId: userId,
            ipAddress: ipAddress,
            expiresAt: DateTime.UtcNow.AddHours(1)
        );
    }

    public static JwtKeyGenerationUserData CreateForRefreshToken(string userId, string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new Exception("User ID cannot be empty");

        if (string.IsNullOrWhiteSpace(ipAddress))
            throw new Exception("IP address cannot be empty");

        return new JwtKeyGenerationUserData(
            userId: userId,
            ipAddress: ipAddress,
            expiresAt: DateTime.UtcNow.AddDays(30)
        );
    }
}