using System.IdentityModel.Tokens.Jwt;
using Grpc.Core;
using Microsoft.IdentityModel.Tokens;

public class JwtValidator : IJwtValidator
{
    private readonly TokenValidationParameters _validationParameters;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly IRedisRepository _redisRepository;

    public JwtValidator(TokenValidationParameters validationParameters, IRedisRepository redisRepository)
    {
        _validationParameters = validationParameters ??
            throw new ArgumentNullException(nameof(validationParameters));
        _tokenHandler = new JwtSecurityTokenHandler();
        _redisRepository = redisRepository;
    }

    public async Task ValidateRefreshRevocation(string token)
    {
        string userId = GetClaimValue(token, "sub");
        string tokenId = GetClaimValue(token, "jti");

        if (!await _redisRepository.KeyExistsAsync($"{userId}:refresh:{tokenId}"))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Provided session was revoked and doesn't exist anymore"));
        }
    }

    public async Task ValidateAccessRevocation(string token)
    {
        string userId = GetClaimValue(token, "sub");
        string tokenId = GetClaimValue(token, "jti");

        string? lastTokenResetRaw =
            await _redisRepository.GetStringAsync($"{userId}:lastTokenReset");
        if (string.IsNullOrEmpty(lastTokenResetRaw))
        {
            if (!await _redisRepository.SetStringAsync($"{userId}:lastTokenReset", "1"))
            {
                throw new RpcException(new Status(StatusCode.DataLoss,
                    "No last token reset date was found and couldn't recreate it"));
            }

            lastTokenResetRaw = "1";
        }
        long lastTokenResetUnix = long.Parse(lastTokenResetRaw);
        DateTime lastTokenReset = DateTimeOffset.FromUnixTimeSeconds(lastTokenResetUnix).UtcDateTime;

        string iatRaw = GetClaimValue(token, "iat");
        long iatUnix = long.Parse(iatRaw);
        DateTime issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatUnix).UtcDateTime;
        if (DateTime.Compare(issuedAt, lastTokenReset) == -1)
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Provided session was revoked and doesn't exist anymore"));
        }

        bool isBlacklisted = await _redisRepository.KeyExistsAsync(
            $"{userId}:blacklist:{tokenId}");
        if (isBlacklisted)
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Provided session was revoked and doesn't exist anymore"));
        }
    }

    public void ValidateToken(string token, string audience = "")
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Token must be provided"));

        try
        {
            _tokenHandler.ValidateToken(token, _validationParameters, out var validatedToken);

            {
                if (!(validatedToken is JwtSecurityToken jwt) ||
                    !_validationParameters.ValidAlgorithms.Contains(jwt.Header.Alg))
                {
                    throw new RpcException(new Status(StatusCode.InvalidArgument,
                        "Invalid token alg"));
                }
            }

            {
                if (!(validatedToken is JwtSecurityToken jwt) ||
                    !jwt.Audiences.Contains(audience))
                {
                    throw new RpcException(new Status(StatusCode.InvalidArgument,
                        "Invalid audience"));
                }
            }

            return;
        }
        catch (SecurityTokenExpiredException)
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Token is expired"));
        }
        catch (SecurityTokenException)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Token validation failed"));
        }
        catch (Exception)
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Token validation error"));
        }
    }

    public static string GetClaimValue(string token, string claimName)
    {
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Token is null or empty");

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        string? claim = jwtToken.Claims.FirstOrDefault(c => c.Type == claimName)?.Value;
        if (string.IsNullOrEmpty(claim))
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "This token doesn't provide enough data"));

        return claim;
    }
}
