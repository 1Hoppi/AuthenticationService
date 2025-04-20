using Authenticator;
using Grpc.Core;
using Google.Protobuf.WellKnownTypes;

public class KeyAccessPointController : KeyAccessPoint.KeyAccessPointBase
{
    private readonly KeyAccessPointCommandHelper _commandHelper;

    public KeyAccessPointController(KeyAccessPointCommandHelper commandHelper)
    {
        _commandHelper = commandHelper;
    }

    public override Task<PublicKeyReply> GetPublicKey(Empty request, ServerCallContext context)
    {
        return Task.FromResult(_commandHelper.GetPublicKey());
    }
}