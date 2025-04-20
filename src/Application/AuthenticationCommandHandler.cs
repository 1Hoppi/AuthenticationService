using Authenticator;
using Grpc.Core;
using JwtValidator;
using System.IdentityModel.Tokens.Jwt;

public sealed class AuthenticationCommandHandler
{
    private readonly IKeyProvider _keyProvider;
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IIpResolver _ipResolver;
    private readonly IJwtValidator _jwtValidator;

    public AuthenticationCommandHandler(IKeyProvider keyProvider, IJwtTokenGenerator jwtTokenGenerator, IIpResolver ipResolver, IJwtValidator jwtValidator)
    {
        _keyProvider = keyProvider;
        _jwtTokenGenerator = jwtTokenGenerator;
        _ipResolver = ipResolver;
        _jwtValidator = jwtValidator;
    }

    public async Task<TokenSet> RefreshToken(RefreshTokenData request, ServerCallContext context)
    {
        bool isValid = _jwtValidator.ValidateRefreshToken(request.RefreshToken, _keyProvider.GetPublicRsaSecurityKey());

        if (!isValid)
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid or expired refresh token"));
        }

        // Check if it's in DB

        // Move this big claim check to the lib     /\/\/\/
        var jwt = new JwtSecurityToken(request.RefreshToken);

        var subClaim = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub);
        if (subClaim == null || string.IsNullOrEmpty(subClaim.Value))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Refresh token must contain Sub claim"));
        }
        //      /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/

        string userId = subClaim.Value; // change to ID
        string ipAddress = await _ipResolver.GetIpFromContext(context); // change to X-Forwarded-For format

        return new TokenSet()
        {
            AccessToken = _jwtTokenGenerator.CreateAccessKey(
                JwtKeyGenerationUserData.CreateForAccessToken(userId, ipAddress)),
            RefreshToken = _jwtTokenGenerator.CreateRefreshKey(
                JwtKeyGenerationUserData.CreateForRefreshToken(userId, ipAddress))
        };
    }

    public async Task<TokenSet> Login(LoginData request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Username and password can't be empty"));
        }

        /* TODO:
        Check password hash from DB
        Get subject ID by name
        Add important claims about the subject
        Change IP address receiving logic (for proxy with "X-Forwarded-For")
        Save refresh token to DB
        Create a library for JwtValidator
        Check if refresh token is in DB
        Add claim checks in the lib
        */

        string userId = request.Username; // change to ID
        string ipAddress = await _ipResolver.GetIpFromContext(context); // change to X-Forwarded-For format

        return new TokenSet()
        {
            AccessToken = _jwtTokenGenerator.CreateAccessKey(
                JwtKeyGenerationUserData.CreateForAccessToken(userId, ipAddress)),
            RefreshToken = _jwtTokenGenerator.CreateRefreshKey(
                JwtKeyGenerationUserData.CreateForRefreshToken(userId, ipAddress))
        };
    }
}