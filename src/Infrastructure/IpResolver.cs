using Grpc.Core;

public class IpResolver : IIpResolver
{
    public string GetIp(ServerCallContext context)
    {
        var httpContext = context.GetHttpContext();

        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();

        var ip = !string.IsNullOrEmpty(forwardedFor)
            ? forwardedFor.Split(',')[0].Trim()
            : remoteIp;

        return ip ?? "unknown";
    }

    public string GetIpBehindProxy(ServerCallContext context)
    {
        var httpContext = context.GetHttpContext();

        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();

        var ip = !string.IsNullOrEmpty(forwardedFor) ? forwardedFor.Split(',')[0].Trim() : "unknown";

        return ip ?? "unknown";
    }
}
