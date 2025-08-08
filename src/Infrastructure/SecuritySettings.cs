public class SecuritySettings
{
    public string Pepper { get; set; } = string.Empty;
    public string JwtPrivateKey { get; set; } = string.Empty;
    public string RedisConnectionString { get; set; } = string.Empty;
    public string PgSqlConnectionString { get; set; } = string.Empty;
}
