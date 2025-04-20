using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

public class KeyProvider : IKeyProvider
{
    private RsaSecurityKey? publicRsaSecurityKey = null;
    private string? publicRsaSecurityKeyString = null;
    private SigningCredentials? signingCredentials = null;

    public KeyProvider()
    {
        GenerateKeys();

        if (signingCredentials == null || publicRsaSecurityKey == null || publicRsaSecurityKeyString == null)
        {
            throw new Exception("Key generator fail", new InvalidOperationException());
        }
    }

    public RsaSecurityKey GetPublicRsaSecurityKey()
    {
        return publicRsaSecurityKey!;
    }

    public string GetPublicRsaSecurityKeyString()
    {
        return publicRsaSecurityKeyString!;
    }

    public SigningCredentials GetSigningCredentials()
    {
        return signingCredentials!;
    }

    private void GenerateKeys()
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText("/secrets/private-key.pem"));

            var privateKey = new RsaSecurityKey(rsa.ExportParameters(true));

            publicRsaSecurityKey = new RsaSecurityKey(rsa.ExportParameters(false));
            signingCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);
            publicRsaSecurityKeyString = rsa.ExportSubjectPublicKeyInfoPem();
        }
        catch (Exception ex)
        {
            throw new Exception("Couldn't generate keys", ex);
        }
    }
}