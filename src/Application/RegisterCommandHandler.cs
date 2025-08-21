using Authenticator;
using Grpc.Core;

public sealed class RegisterCommandHandler
{
    private readonly IHasher _hasher;
    private readonly IRedisRepository _redisRepository;
    private readonly IUserCredentialsService _userCredentialsService;
    private readonly LoginCommandHandler _loginCommandHandler;

    public RegisterCommandHandler(
        IHasher hasher,
        IRedisRepository redisRepository,
        IUserCredentialsService userCredentialsService,
        LoginCommandHandler loginCommandHandler)
    {
        _hasher = hasher;
        _redisRepository = redisRepository;
        _userCredentialsService = userCredentialsService;
        _loginCommandHandler = loginCommandHandler;
    }

    public async Task<TokenPairDto> Register(UserCredentialsDto request, ServerCallContext context)
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
        TokenPairDto tokenPair = await _loginCommandHandler.Login(new UserCredentialsDto
        {
            Username = request.Username,
            Password = request.Password
        }, context);

        return tokenPair;
    }
}
