using Microsoft.IdentityModel.Tokens;

public interface IKeyProvider
{
    RsaSecurityKey GetPublicRsaSecurityKey();
    string GetPublicRsaSecurityKeyString();
    SigningCredentials GetSigningCredentials();
}