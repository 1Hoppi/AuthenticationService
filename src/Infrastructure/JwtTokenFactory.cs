using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;

public class JwtTokenFactory : IJwtTokenFactory
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IKeyProvider _keyProvider;

    public JwtTokenFactory(IOptionsMonitor<JwtSettings> options, IKeyProvider keyProvider)
    {
        _options = options;
        _keyProvider = keyProvider;
    }

    public TokenData NewAccessToken(string userId, string ipAddress)
    {
        return CreateToken(new TokenData()
            .WithTokenId(Guid.NewGuid().ToString())
            .WithUserId(userId)
            .WithIpAddress(ipAddress)
            .WithExpiresAt(DateTime.UtcNow.AddMinutes(
                _options.CurrentValue.AccessTokenMinutesToExist))
            .WithIssuedAt(DateTime.UtcNow)
            .WithAudience(_options.CurrentValue.AccessAudience)
            .WithSigningCredentials(_keyProvider.GetSigningCredentials()));
    }

    public TokenData NewRefreshToken(string userId, string ipAddress)
    {
        return CreateToken(new TokenData()
            .WithTokenId(Guid.NewGuid().ToString())
            .WithUserId(userId)
            .WithIpAddress(ipAddress)
            .WithExpiresAt(DateTime.UtcNow.AddMinutes(
                _options.CurrentValue.RefreshTokenMinutesToExist))
            .WithIssuedAt(DateTime.UtcNow)
            .WithAudience(_options.CurrentValue.RefreshAudience)
            .WithSigningCredentials(_keyProvider.GetSigningCredentials()));
    }

    public TokenData CreateToken(TokenData tokenData)
    {
        var issuedAtUnix = new DateTimeOffset(tokenData.IssuedAt).ToUnixTimeSeconds();

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, tokenData.UserId),
            new Claim(JwtRegisteredClaimNames.Jti, tokenData.TokenId),
            new Claim("ip", tokenData.IpAddress),
            new Claim(JwtRegisteredClaimNames.Iat, issuedAtUnix.ToString(), ClaimValueTypes.Integer64),
        };

        var token = new JwtSecurityToken(
            audience: tokenData.Audience,
            claims: claims,
            expires: tokenData.ExpiresAt,
            signingCredentials: tokenData.SigningCredentials
        );

        tokenData.WithToken(new JwtSecurityTokenHandler().WriteToken(token));

        return tokenData;
    }
}
