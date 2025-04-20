public interface IJwtTokenGenerator
{
    public string CreateAccessKey(JwtKeyGenerationUserData userData);
    public string CreateRefreshKey(JwtKeyGenerationUserData userData);
}