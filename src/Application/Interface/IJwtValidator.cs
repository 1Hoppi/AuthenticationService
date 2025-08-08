public interface IJwtValidator
{
    public void ValidateToken(string token);
    public Task ValidateAccessRevocation(string token);
    public Task ValidateRefreshRevocation(string token);
}
