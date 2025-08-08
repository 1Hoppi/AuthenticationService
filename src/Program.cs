using StackExchange.Redis;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

public static class Program
{
    public static void Main(string[] args)
    {
        // This is vital as JwtSecurityTokenHandler changes claim types,
        // for example sub -> NameClaimType
        JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

        var builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddJsonFile(
            "appsettings.json", optional: false, reloadOnChange: true);

        var securitySettingsSection = builder.Configuration.GetSection("Security");
        var securitySettings = securitySettingsSection.Get<SecuritySettings>();
        if (securitySettings == null)
        {
            throw new Exception("Couldn't get SecuritySettings from env");
        }

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
            });
        });

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            // Wrom who it's allowed to receive X-Forwarded-For
            // For example, if there's nginx behind this service
            options.KnownProxies.Add(IPAddress.Parse("127.0.0.1")); // Or IP of the proxy server
            // Or:
            // options.KnownNetworks.Add(new IPNetwork(IPAddress.Parse("192.168.0.0"), 24));
        });

        builder.Services.AddGrpc().AddJsonTranscoding();

        // Request handling & processing
        builder.Services.AddScoped<AuthenticationCommandHandler>();
        builder.Services.AddScoped<IIpResolver, IpResolver>();
        builder.Services.AddScoped<IHasher, Hasher>();

        // JWT
        builder.Services.AddScoped<IJwtValidator>(provider =>
        {
            var optionsMonitor = provider.GetRequiredService<IOptionsMonitor<JwtSettings>>();
            var keyProvider = provider.GetRequiredService<IKeyProvider>();
            var redisRepository = provider.GetRequiredService<IRedisRepository>();

            var key = keyProvider.GetSecurityKey();

            var parameters = new TokenValidationParameters
            {
                ValidAlgorithms =
                [
                    SecurityAlgorithms.HmacSha256
                ],
                ValidateIssuer = false,
                ValidateAudience = true,
                ValidAudiences =
                [
                    optionsMonitor.CurrentValue.AccessAudience,
                    optionsMonitor.CurrentValue.RefreshAudience
                ],
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateLifetime = true
            };

            return new JwtValidator(parameters, redisRepository);
        });
        builder.Services.AddScoped<IJwtTokenFactory, JwtTokenFactory>();

        // Security & Env
        builder.Services.Configure<SecuritySettings>(securitySettingsSection);
        builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
        builder.Services.AddSingleton<IKeyProvider, KeyProvider>();

        // Redis
        builder.Services.AddScoped<IRedisRepository, RedisRepository>();
        builder.Services.AddSingleton<IConnectionMultiplexer>(provider =>
        {
            var connectionString = securitySettings.RedisConnectionString;
            return ConnectionMultiplexer.Connect(connectionString);
        });

        // Postgres
        builder.Services.AddScoped<IPgSqlRepository, PgSqlRepository>(provider =>
        {
            var connectionString = securitySettings.PgSqlConnectionString;
            return new PgSqlRepository(connectionString);
        });

        var app = builder.Build();

        // Cors & Forwarding
        app.UseCors("AllowAll");
        app.UseForwardedHeaders();

        app.MapGrpcService<AuthenticationController>();
        app.Run();
    }
}
