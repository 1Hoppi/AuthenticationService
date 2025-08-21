using Authenticator;
using Grpc.Core;
using Microsoft.Extensions.Options;
using Google.Protobuf.WellKnownTypes;

public sealed class LogoutCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IJwtValidator _jwtValidator;
    private readonly IRedisRepository _redisRepository;

    public LogoutCommandHandler(
        IOptionsMonitor<JwtSettings> options,
        IJwtValidator jwtValidator,
        IRedisRepository redisRepository)
    {
        _options = options;
        _jwtValidator = jwtValidator;
        _redisRepository = redisRepository;
    }

    public async Task<Empty> Logout(TokenPairDto request, ServerCallContext context)
    {
        string accessUserId = JwtValidator.GetClaimValue(request.AccessToken, "sub");
        string accessTokenId = JwtValidator.GetClaimValue(request.AccessToken, "jti");
        string refreshUserId = JwtValidator.GetClaimValue(request.RefreshToken, "sub");
        string refreshTokenId = JwtValidator.GetClaimValue(request.RefreshToken, "jti");

        // if (!accessUserId.Equals(refreshUserId))
        // {
        //     throw new RpcException(new Status(StatusCode.InvalidArgument,
        //         "Tokens with different user IDs were used"));
        // }
        try
        {
            _jwtValidator.ValidateToken(request.AccessToken, _options.CurrentValue.AccessAudience);
            await _jwtValidator.ValidateAccessRevocation(request.AccessToken);

            if (!await _redisRepository.SetStringAsync(
                $"{accessUserId}:blacklist:{accessTokenId}",
                "",
                TimeSpan.FromMinutes(_options.CurrentValue.AccessTokenMinutesToExist)))
            {
                throw new RpcException(new Status(StatusCode.Internal,
                    "Couldn't revoke access token"));
            }
        }
        catch (RpcException) { }

        try
        {
            _jwtValidator.ValidateToken(request.RefreshToken, _options.CurrentValue.RefreshAudience);
            await _jwtValidator.ValidateRefreshRevocation(request.RefreshToken);

            if (!await _redisRepository.DeleteKeyAsync($"{refreshUserId}:refresh:{refreshTokenId}"))
            {
                throw new RpcException(new Status(StatusCode.Internal,
                    "Couldn't revoke refresh token"));
            }
        }
        catch (RpcException) { }

        return new Empty();
    }

    public async Task<Empty> LogoutAll(AccessTokenDto request, ServerCallContext context)
    {
        _jwtValidator.ValidateToken(request.AccessToken, _options.CurrentValue.RefreshAudience);
        await _jwtValidator.ValidateAccessRevocation(request.AccessToken);

        string accessUserId = JwtValidator.GetClaimValue(request.AccessToken, "sub");

        try
        {
            _ = await _redisRepository.DeleteKeysByPatternAsync($"{accessUserId}:refresh:*");
        }
        catch (Exception)
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't revoke all the tokens"));
        }

        DateTime now = DateTime.UtcNow;
        long unixTime = new DateTimeOffset(now).ToUnixTimeSeconds();
        string unixTimeString = unixTime.ToString();

        if (!await _redisRepository.SetStringAsync(
            $"{accessUserId}:lastTokenReset", unixTimeString))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't revoke refresh token"));
        }

        return new Empty();
    }
}
