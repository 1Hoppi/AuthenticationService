using Grpc.Core;

public class IpResolver : IIpResolver
{
    public Task<string> GetIpFromContext(ServerCallContext context)
    {
        var peer = context.Peer;
        var ip = peer.Split(':')[1];

        if (ip.StartsWith("[") && ip.EndsWith("]"))
        {
            ip = ip[1..^1];
        }

        return Task.FromResult(ip);
    }
}