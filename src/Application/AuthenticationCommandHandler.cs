using Authenticator;
using Grpc.Core;
using Npgsql;
using Microsoft.Extensions.Options;
using Google.Protobuf.WellKnownTypes;

public sealed class AuthenticationCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IJwtTokenFactory _jwtTokenFactory;
    private readonly IIpResolver _ipResolver;
    private readonly IJwtValidator _jwtValidator;
    private readonly IHasher _hasher;
    private readonly IRedisRepository _redisRepository;
    private readonly IUserCredentialsService _userCredentialsService;

    public AuthenticationCommandHandler(IOptionsMonitor<JwtSettings> options,
        IJwtTokenFactory jwtTokenFactory,
        IIpResolver ipResolver,
        IJwtValidator jwtValidator,
        IHasher hasher,
        IRedisRepository redisRepository,
        IUserCredentialsService userCredentialsService)
    {
        _options = options;
        _jwtTokenFactory = jwtTokenFactory;
        _ipResolver = ipResolver;
        _jwtValidator = jwtValidator;
        _hasher = hasher;
        _redisRepository = redisRepository;
        _userCredentialsService = userCredentialsService;
    }

    public async Task<TokenSet> Register(LoginCredentials request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Username and password can't be empty"));
        }
        if (request.Username.Length < 4 || request.Username.Length > 16)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Username must have at least 4 " +
                "and up to 16 characters"));
        }
        if (request.Password.Length < 6 || request.Password.Length > 32)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Password must have at least 6 " +
                "and up to 32 characters"));
        }

        var hashData = _hasher.HashPassword(request.Password);
        byte[] hash = hashData.Item1;
        byte[] salt = hashData.Item2;

        bool available = await _userCredentialsService.GetUsernameAvailability(request.Username);
        if (!available)
        {
            throw new RpcException(new Status(StatusCode.AlreadyExists, "This username has already been taken"));
        }

        // Create user id
        var userId = Guid.NewGuid();

        // Create a new user
        if (!await _redisRepository.SetStringAsync($"{userId}:lastTokenReset", "1"))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't store last token reset data"));
        }

        int affectedRows = await _userCredentialsService.CreateNewUser(
            userId, request.Username, hash, salt);
        if (affectedRows == 0)
        {
            throw new RpcException(new Status(StatusCode.Internal, "Internal error while writing data"));
        }

        // Create and return JWT keys (Login)
        TokenSet tokenSet = await this.Login(new LoginCredentials
        {
            Username = request.Username,
            Password = request.Password
        }, context);

        return tokenSet;
    }

    public async Task<TokenSet> Login(LoginCredentials request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Username and password can't be empty"));
        }

        UserCredentials? credentials = await _userCredentialsService.GetCredentialsByUsernameAsync(request.Username);
        if (credentials == null)
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Wrong username or password"));
        }

        if (credentials.PasswordHash == null || credentials.PasswordSalt == null)
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Internal error while reading data"));
        }

        byte[] currentHash = _hasher.HashPassword(request.Password, credentials.PasswordSalt).Item1;

        if (!credentials.PasswordHash.SequenceEqual(currentHash))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Wrong username or password"));
        }

        string userIdString = credentials.UserId.ToString();
        string ipAddress = _ipResolver.GetIpBehindProxy(context);

        var accessToken = _jwtTokenFactory.NewAccessToken(userIdString, ipAddress);
        var refreshToken = _jwtTokenFactory.NewRefreshToken(userIdString, ipAddress);

        if (!await _redisRepository.SetStringAsync(
            $"{userIdString}:refresh:{refreshToken.TokenId}",
            "",
            TimeSpan.FromMinutes(_options.CurrentValue.RefreshTokenMinutesToExist)))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't store the new refresh token"));
        }

        return new TokenSet()
        {
            AccessToken = accessToken.Token,
            RefreshToken = refreshToken.Token
        };
    }

    public async Task<TokenSet> RefreshToken(TokenSet request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "No token was provided"));
        }

        string userIp = _ipResolver.GetIpBehindProxy(context);

        _jwtValidator.ValidateToken(request.RefreshToken);
        await _jwtValidator.ValidateRefreshRevocation(request.RefreshToken);

        // Implies that the existence of useId and tokenId was checked during
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
            _jwtValidator.ValidateToken(request.AccessToken);
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

        return new TokenSet()
        {
            AccessToken = accessToken.Token,
            RefreshToken = refreshToken.Token
        };
    }

    public async Task<Empty> Logout(TokenSet request, ServerCallContext context)
    {
        _jwtValidator.ValidateToken(request.AccessToken);
        await _jwtValidator.ValidateAccessRevocation(request.AccessToken);

        _jwtValidator.ValidateToken(request.RefreshToken);
        await _jwtValidator.ValidateRefreshRevocation(request.RefreshToken);

        string accessUserId = JwtValidator.GetClaimValue(request.AccessToken, "sub");
        string accessTokenId = JwtValidator.GetClaimValue(request.AccessToken, "jti");
        string refreshUserId = JwtValidator.GetClaimValue(request.RefreshToken, "sub");
        string refreshTokenId = JwtValidator.GetClaimValue(request.RefreshToken, "jti");

        if (!accessUserId.Equals(refreshUserId))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Tokens with different user IDs were used"));
        }

        if (!await _redisRepository.SetStringAsync(
            $"{accessUserId}:blacklist:{accessTokenId}",
            "",
            TimeSpan.FromMinutes(_options.CurrentValue.AccessTokenMinutesToExist)))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't revoke access token"));
        }

        if (!await _redisRepository.DeleteKeyAsync($"{refreshUserId}:refresh:{refreshTokenId}"))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't revoke refresh token"));
        }

        return new Empty();
    }

    public async Task<Empty> LogoutAll(AccessToken request, ServerCallContext context)
    {
        _jwtValidator.ValidateToken(request.AccessToken_);
        await _jwtValidator.ValidateAccessRevocation(request.AccessToken_);

        string accessUserId = JwtValidator.GetClaimValue(request.AccessToken_, "sub");

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
