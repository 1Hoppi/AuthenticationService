using Authenticator;
using Grpc.Core;
using Google.Protobuf.WellKnownTypes;

public class AuthenticationController : AuthenticationService.AuthenticationServiceBase
{
    private readonly AuthenticationCommandHandler _commandHandler;

    public AuthenticationController(AuthenticationCommandHandler commandHandlper)
    {
        _commandHandler = commandHandlper;
    }

    public override async Task<TokenSet> Register(LoginCredentials request, ServerCallContext context)
    {
        return await _commandHandler.Register(request, context);
    }

    public override async Task<TokenSet> Login(LoginCredentials request, ServerCallContext context)
    {
        return await _commandHandler.Login(request, context);
    }

    public override async Task<TokenSet> Refresh(TokenSet request, ServerCallContext context)
    {
        return await _commandHandler.RefreshToken(request, context);
    }

    public override async Task<Empty> Logout(TokenSet request, ServerCallContext context)
    {
        return await _commandHandler.Logout(request, context);
    }

    public override async Task<Empty> LogoutAll(AccessToken request, ServerCallContext context)
    {
        return await _commandHandler.LogoutAll(request, context);
    }
}
