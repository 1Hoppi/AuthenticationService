using Grpc.Net.Client;
using System.ComponentModel;
using JwtValidator;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
            });
        });

        builder.Services.AddGrpc().AddJsonTranscoding();

        builder.Services.AddScoped<AuthenticationCommandHandler>();
        builder.Services.AddScoped<KeyAccessPointCommandHandler>();
        builder.Services.AddScoped<IIpResolver, IpResolver>();
        builder.Services.AddScoped<IJwtValidator, JwtValidator.JwtValidator>();
        builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
        builder.Services.AddSingleton<IKeyProvider, KeyProvider>();

        var app = builder.Build();

        app.UseCors("AllowAll");

        app.MapGrpcService<AuthenticationController>();
        app.MapGrpcService<KeyAccessPointController>();

        app.Run();
    }
}
