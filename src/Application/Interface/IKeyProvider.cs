using Microsoft.IdentityModel.Tokens;

public interface IKeyProvider
{
    public SymmetricSecurityKey GetSecurityKey();
    public SigningCredentials GetSigningCredentials();
}
