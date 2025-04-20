using Authenticator;
using Grpc.Core;
using Google.Protobuf.WellKnownTypes;

public class AuthenticationController : Authentication.AuthenticationBase
{
    private readonly AuthenticationCommandHelper _commandHelper;

    public AuthenticationController(AuthenticationCommandHelper commandHelper)
    {
        _commandHelper = commandHelper;
    }

    public override async Task<TokenSet> Login(LoginData request, ServerCallContext context)
    {
        return await _commandHelper.Login(request, context);
    }

    public override async Task<TokenSet> RefreshToken(RefreshTokenData request, ServerCallContext context)
    {
        return await _commandHelper.RefreshToken(request, context);
    }
}
