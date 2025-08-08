using Authenticator;
using Grpc.Core;
using Npgsql;
using Microsoft.Extensions.Options;
using Google.Protobuf.WellKnownTypes;

public sealed class AuthenticationCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IKeyProvider _keyProvider;
    private readonly IJwtTokenFactory _jwtTokenFactory;
    private readonly IIpResolver _ipResolver;
    private readonly IJwtValidator _jwtValidator;
    private readonly IHasher _hasher;
    private readonly IPgSqlRepository _pgSqlRepository;
    private readonly IRedisRepository _redisRepository;

    public AuthenticationCommandHandler(IOptionsMonitor<JwtSettings> options,
        IKeyProvider keyProvider, IJwtTokenFactory jwtTokenFactory,
        IIpResolver ipResolver, IJwtValidator jwtValidator, IHasher hasher,
        IPgSqlRepository pgSqlRepository, IRedisRepository redisRepository)
    {
        _options = options;
        _keyProvider = keyProvider;
        _jwtTokenFactory = jwtTokenFactory;
        _ipResolver = ipResolver;
        _jwtValidator = jwtValidator;
        _hasher = hasher;
        _pgSqlRepository = pgSqlRepository;
        _redisRepository = redisRepository;
    }

    public async Task<Empty> Register(RegisterData request, ServerCallContext context)
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

        // Check if usename is free
        {
            var sql = $"SELECT EXISTS(SELECT 1 FROM user_credentials WHERE username = @value)";
            var parameter1 = new NpgsqlParameter("value", request.Username);
            var result = await _pgSqlRepository.ExecuteScalarAsync(sql, parameter1);
            if (result == null || (bool)result)
            {
                throw new RpcException(new Status(StatusCode.AlreadyExists, "This username has already been taken"));
            }
        }

        // Create user & token data 
        var userId = Guid.NewGuid();

        // Create a new user
        if (!await _redisRepository.SetStringAsync($"{userId}:lastTokenReset", "1"))
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Couldn't store last token reset data"));
        }

        {
            // Postgres
            var sql = "INSERT INTO user_credentials (user_id, password_hash, password_salt, username) " +
                "VALUES (@user_id, @hash, @salt, @username)";
            var parameters = new NpgsqlParameter[]
            {
            new NpgsqlParameter("user_id", userId),
            new NpgsqlParameter("hash", hash),
            new NpgsqlParameter("salt", salt),
            new NpgsqlParameter("username", request.Username),
            };

            int affectedRows = await _pgSqlRepository.ExecuteNonQueryAsync(sql, parameters);

            if (affectedRows == 0)
            {
                throw new RpcException(new Status(StatusCode.Internal, "Internal error while writing data"));
            }
        }

        // // Create and return JWT keys (Login)
        // TokenSet tokenSet = await this.Login(new LoginData
        // {
        //     Username = request.Username,
        //     Password = request.Password
        // }, context);

        return new Empty();
    }

    public async Task<TokenSet> Login(LoginData request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Username and password can't be empty"));
        }

        byte[] actualSalt, actualHash;
        Guid userId;

        {
            var sql = "SELECT password_hash, password_salt, user_id FROM user_credentials WHERE username = @username";
            var parameters = new NpgsqlParameter("username", request.Username);
            using (NpgsqlDataReader reader = await _pgSqlRepository.ExecuteReaderAsync(sql, parameters))
            {
                if (!reader.HasRows)
                {
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Wrong username or password"));
                }

                try
                {
                    reader.Read();
                    actualHash = reader.GetFieldValue<byte[]>(reader.GetOrdinal("password_hash"));
                    actualSalt = reader.GetFieldValue<byte[]>(reader.GetOrdinal("password_salt"));
                    userId = reader.GetFieldValue<Guid>(reader.GetOrdinal("user_id"));
                }
                catch (Exception)
                {
                    throw new RpcException(new Status(StatusCode.Internal, "Internal error while reading data"));
                }
            }
        }

        if (actualHash == null || actualSalt == null)
        {
            throw new RpcException(new Status(StatusCode.Internal,
                "Internal error while reading data"));
        }

        byte[] currentHash = _hasher.HashPassword(request.Password, actualSalt).Item1;

        if (!actualHash.SequenceEqual(currentHash))
        {
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Wrong username or password"));
        }

        string userIdString = userId.ToString();
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

    public async Task<TokenSet> RefreshToken(RefreshData request, ServerCallContext context)
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

    public async Task<Empty> Logout(LogoutData request, ServerCallContext context)
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

    public async Task<Empty> LogoutAll(LogoutAllData request, ServerCallContext context)
    {
        _jwtValidator.ValidateToken(request.AccessToken);
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
