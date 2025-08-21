using Authenticator;
using Grpc.Core;
using Microsoft.Extensions.Options;

public sealed class RefreshCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IJwtTokenFactory _jwtTokenFactory;
    private readonly IIpResolver _ipResolver;
    private readonly IJwtValidator _jwtValidator;
    private readonly IRedisRepository _redisRepository;

    public RefreshCommandHandler(
        IOptionsMonitor<JwtSettings> options,
        IJwtTokenFactory jwtTokenFactory,
        IIpResolver ipResolver,
        IJwtValidator jwtValidator,
        IRedisRepository redisRepository)
    {
        _options = options;
        _jwtTokenFactory = jwtTokenFactory;
        _ipResolver = ipResolver;
        _jwtValidator = jwtValidator;
        _redisRepository = redisRepository;
    }

    public async Task<TokenPairDto> RefreshToken(TokenPairDto request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "No token was provided"));
        }

        string userIp = _ipResolver.GetIpBehindProxy(context);

        _jwtValidator.ValidateToken(request.RefreshToken, _options.CurrentValue.RefreshAudience);
        await _jwtValidator.ValidateRefreshRevocation(request.RefreshToken);

        // Implies that the existence of userId and tokenId was checked during
        // validation and ip is always present
        string refreshUserId = JwtValidator.GetClaimValue(request.RefreshToken, "sub");
        string refreshTokenId = JwtValidator.GetClaimValue(request.RefreshToken, "jti");
        string refreshIpAddress = JwtValidator.GetClaimValue(request.RefreshToken, "ip");

        if (!userIp.Equals(refreshIpAddress))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "You can't update your session on this device with provided tokens"));
        }

        // Check if it's in redis
        if (!await _redisRepository.KeyExistsAsync($"{refreshUserId}:refresh:{refreshTokenId}"))
        {
            // POSSIBLE ATTACK ON USER IF REACHED THIS /!\
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "This token was revoked"));
        }

        // Implies that the existence of useId and tokenId was checked during
        // validation and ip is always present
        bool isAccessTokenExpired = false;
        try
        {
            _jwtValidator.ValidateToken(request.AccessToken, _options.CurrentValue.AccessAudience);
        }
        catch (RpcException ex)
        {
            if (ex.StatusCode != StatusCode.Unauthenticated)
            {
                throw new RpcException(new Status(StatusCode.Unauthenticated,
                    "Invalid access token"));
            }

            isAccessTokenExpired = true;
        }
        catch (Exception ex)
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Access token validation error" + ex));
        }

        await _jwtValidator.ValidateAccessRevocation(request.AccessToken);

        string accessUserId = JwtValidator.GetClaimValue(request.AccessToken, "sub");
        string accessTokenId = JwtValidator.GetClaimValue(request.AccessToken, "jti");
        string accessIpAddress = JwtValidator.GetClaimValue(request.AccessToken, "ip");

        if (!accessUserId.Equals(refreshUserId) || !accessIpAddress.Equals(refreshIpAddress))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Invalid pair of tokens"));
        }

        // Revoke refresh token
        if (!await _redisRepository.DeleteKeyAsync($"{refreshUserId}:refresh:{refreshTokenId}"))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't revoke provided token"));
        }

        // Create new tokens
        var accessToken = _jwtTokenFactory.NewAccessToken(refreshUserId, refreshIpAddress);
        var refreshToken = _jwtTokenFactory.NewRefreshToken(refreshUserId, refreshIpAddress);

        // Revoke old access token if needed
        if (!isAccessTokenExpired)
        {
            await _redisRepository.SetStringAsync($"{refreshUserId}:blacklist:{accessTokenId}",
                "",
                TimeSpan.FromMinutes(_options.CurrentValue.AccessTokenMinutesToExist));

            if (!await _redisRepository.SetStringAsync(
                $"{refreshUserId}:refresh:{refreshToken.TokenId}",
                "",
                TimeSpan.FromMinutes(_options.CurrentValue.RefreshTokenMinutesToExist)))
            {
                throw new RpcException(new Status(StatusCode.Internal,
                    "Couldn't store the new refresh token"));
            }
        }

        return new TokenPairDto()
        {
            AccessToken = accessToken.Token,
            RefreshToken = refreshToken.Token
        };
    }
}
