using Authenticator;
using Grpc.Core;
using Google.Protobuf.WellKnownTypes;

public class AuthenticationController : AuthenticationService.AuthenticationServiceBase
{
    private readonly LoginCommandHandler _loginCommandHandler;
    private readonly LogoutCommandHandler _logoutCommandHandler;
    private readonly RefreshCommandHandler _refreshCommandHandler;
    private readonly RegisterCommandHandler _registerCommandHandler;
    private readonly ValidateCommandHandler _validateCommandHandler;

    public AuthenticationController(
        LoginCommandHandler loginCommandHandler,
        LogoutCommandHandler logoutCommandHandler,
        RefreshCommandHandler refreshCommandHandler,
        RegisterCommandHandler registerCommandHandler,
        ValidateCommandHandler validateCommandHandler)
    {
        _loginCommandHandler = loginCommandHandler;
        _logoutCommandHandler = logoutCommandHandler;
        _refreshCommandHandler = refreshCommandHandler;
        _registerCommandHandler = registerCommandHandler;
        _validateCommandHandler = validateCommandHandler;
    }

    public override async Task<RegisterResponse> Register(Authenticator.RegisterRequest request, ServerCallContext context)
    {
        TokenPairDto result = await _registerCommandHandler.Register(new UserCredentialsDto
        {
            Username = request.Username,
            Password = request.Password,
        }, context);

        return new RegisterResponse
        {
            AccessToken = result.AccessToken,
            RefreshToken = result.RefreshToken,
        };
    }

    public override async Task<LoginResponse> Login(Authenticator.LoginRequest request, ServerCallContext context)
    {
        TokenPairDto result = await _loginCommandHandler.Login(new UserCredentialsDto
        {
            Username = request.Username,
            Password = request.Password,
        }, context);

        return new LoginResponse
        {
            AccessToken = result.AccessToken,
            RefreshToken = result.RefreshToken,
        };
    }

    public override async Task<RefreshResponse> Refresh(Authenticator.RefreshRequest request, ServerCallContext context)
    {
        TokenPairDto result = await _refreshCommandHandler.RefreshToken(new TokenPairDto
        {
            AccessToken = request.AccessToken,
            RefreshToken = request.RefreshToken,
        }, context);

        return new RefreshResponse
        {
            AccessToken = result.AccessToken,
            RefreshToken = result.RefreshToken,
        };
    }

    public override async Task<Empty> Logout(LogoutRequest request, ServerCallContext context)
    {
        return await _logoutCommandHandler.Logout(new TokenPairDto
        {
            AccessToken = request.AccessToken,
            RefreshToken = request.RefreshToken,
        }, context);
    }

    public override async Task<Empty> LogoutAll(LogoutAllRequest request, ServerCallContext context)
    {
        return await _logoutCommandHandler.LogoutAll(new AccessTokenDto
        {
            AccessToken = request.AccessToken
        }, context);
    }

    public override async Task<ValidateResponse> Validate(ValidateRequest request, ServerCallContext context)
    {
        ValidationResultDto result = await _validateCommandHandler.Validate(new AccessTokenDto
        {
            AccessToken = request.AccessToken
        }, context);

        return new ValidateResponse
        {
            IsValid = result.IsValid
        };
    }
}
