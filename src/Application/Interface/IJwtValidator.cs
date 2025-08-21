public interface IJwtValidator
{
    public void ValidateToken(string token, string audience = "");
    public Task ValidateAccessRevocation(string token);
    public Task ValidateRefreshRevocation(string token);
}
