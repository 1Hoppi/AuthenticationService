using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class JwtTokenGenerator : IJwtTokenGenerator
{
    private readonly IKeyProvider _keyProvider;

    public JwtTokenGenerator(IKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    public string CreateAccessKey(JwtKeyGenerationUserData userData)
    {
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var accessTokenClaims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userData.UserId),
            new Claim("ip", userData.IpAddress),
            new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToString(), ClaimValueTypes.Integer64),
        };

        JwtSecurityToken accessToken = new JwtSecurityToken(
            issuer: "AuthenticationService",
            audience: "ApplicationClient",
            claims: accessTokenClaims,
            expires: userData.ExpiresAt,
            signingCredentials: _keyProvider.GetSigningCredentials()
        );

        return new JwtSecurityTokenHandler().WriteToken(accessToken);
    }

    public string CreateRefreshKey(JwtKeyGenerationUserData userData)
    {
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var refreshTokenId = Guid.NewGuid().ToString();
        var refreshTokenClaims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userData.UserId), // change to ID
            new Claim(JwtRegisteredClaimNames.Jti, refreshTokenId),
            new Claim("ip", userData.IpAddress),
            new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToString(), ClaimValueTypes.Integer64),
        };

        JwtSecurityToken refreshToken = new JwtSecurityToken(
            issuer: "AuthenticationService",
            audience: "ApplicationClient-Refresh",
            claims: refreshTokenClaims,
            expires: userData.ExpiresAt,
            signingCredentials: _keyProvider.GetSigningCredentials()
        );

        return new JwtSecurityTokenHandler().WriteToken(refreshToken);
    }
}