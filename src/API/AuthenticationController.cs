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

    public override async Task<Empty> Register(RegisterData request, ServerCallContext context)
    {
        return await _commandHandler.Register(request, context);
    }

    public override async Task<TokenSet> Login(LoginData request, ServerCallContext context)
    {
        return await _commandHandler.Login(request, context);
    }

    public override async Task<TokenSet> Refresh(RefreshData request, ServerCallContext context)
    {
        return await _commandHandler.RefreshToken(request, context);
    }

    public override async Task<Empty> Logout(LogoutData request, ServerCallContext context)
    {
        return await _commandHandler.Logout(request, context);
    }

    public override async Task<Empty> LogoutAll(LogoutAllData request, ServerCallContext context)
    {
        return await _commandHandler.LogoutAll(request, context);
    }
}
