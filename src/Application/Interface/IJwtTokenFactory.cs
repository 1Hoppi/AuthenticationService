public interface IJwtTokenFactory
{
    public TokenData NewAccessToken(string userId, string ipAddress);
    public TokenData NewRefreshToken(string userId, string ipAddress);
}
