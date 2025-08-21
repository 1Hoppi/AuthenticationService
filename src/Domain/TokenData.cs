using Microsoft.IdentityModel.Tokens;

public class TokenData
{
    public string Token { get; set; } = string.Empty;
    public string TokenId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime IssuedAt { get; set; }
    public string Audience { get; set; } = string.Empty;
    public SigningCredentials SigningCredentials { get; set; } = null!;
}
