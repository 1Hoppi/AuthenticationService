public class JwtSettings
{
    public int AccessTokenMinutesToExist { get; set; }
    public int RefreshTokenMinutesToExist { get; set; }
    public string AccessAudience { get; set; } = null!;
    public string RefreshAudience { get; set; } = null!;
}
