using Authenticator;
using Grpc.Core;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

public sealed class LoginCommandHandler
{
    private readonly IOptionsMonitor<JwtSettings> _options;
    private readonly IJwtTokenFactory _jwtTokenFactory;
    private readonly IIpResolver _ipResolver;
    private readonly IHasher _hasher;
    private readonly IRedisRepository _redisRepository;
    private readonly IUserCredentialsService _userCredentialsService;

    public LoginCommandHandler(
        IOptionsMonitor<JwtSettings> options,
        IJwtTokenFactory jwtTokenFactory,
        IIpResolver ipResolver,
        IHasher hasher,
        IRedisRepository redisRepository,
        IUserCredentialsService userCredentialsService)
    {
        _options = options;
        _jwtTokenFactory = jwtTokenFactory;
        _ipResolver = ipResolver;
        _hasher = hasher;
        _redisRepository = redisRepository;
        _userCredentialsService = userCredentialsService;
    }

    public async Task<TokenPairDto> Login(UserCredentialsDto request, ServerCallContext context)
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

        if (!_hasher.VerifyPassword(request.Password, credentials.PasswordHash, credentials.PasswordSalt))
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

        return new TokenPairDto()
        {
            AccessToken = accessToken.Token,
            RefreshToken = refreshToken.Token
        };
    }
}
