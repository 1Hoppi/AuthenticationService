using Grpc.Core;

public interface IIpResolver
{
    public Task<string> GetIpFromContext(ServerCallContext context);
}