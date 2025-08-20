using Microsoft.IdentityModel.Tokens;

public class TokenData
{
    public string Token { get; private set; } = string.Empty;
    public string TokenId { get; private set; } = string.Empty;
    public string UserId { get; private set; } = string.Empty;
    public string IpAddress { get; private set; } = string.Empty;
    public DateTime ExpiresAt { get; private set; }
    public DateTime IssuedAt { get; private set; }
    public string Audience { get; private set; } = string.Empty;
    public SigningCredentials SigningCredentials { get; private set; } = null!;

    public TokenData WithToken(string token)
    {
        Token = token;
        return this;
    }

    public TokenData WithTokenId(string tokenId)
    {
        TokenId = tokenId;
        return this;
    }

    public TokenData WithUserId(string userId)
    {
        UserId = userId;
        return this;
    }

    public TokenData WithIpAddress(string ipAddress)
    {
        IpAddress = ipAddress;
        return this;
    }

    public TokenData WithExpiresAt(DateTime expiresAt)
    {
        ExpiresAt = expiresAt;
        return this;
    }

    public TokenData WithIssuedAt(DateTime issuedAt)
    {
        IssuedAt = issuedAt;
        return this;
    }

    public TokenData WithAudience(string audience)
    {
        Audience = audience;
        return this;
    }

    public TokenData WithSigningCredentials(SigningCredentials signingCredentials)
    {
        SigningCredentials = signingCredentials;
        return this;
    }
}
