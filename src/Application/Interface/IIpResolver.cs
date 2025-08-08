using Grpc.Core;

public interface IIpResolver
{
    public string GetIp(ServerCallContext context);
    public string GetIpBehindProxy(ServerCallContext context);
}
