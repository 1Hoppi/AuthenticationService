using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public class KeyProvider : IKeyProvider
{
    private readonly string _jwtPrivateKey;
    private SigningCredentials signingCredentials = null!;
    private SymmetricSecurityKey hmacKey = null!;

    public KeyProvider(IOptions<SecuritySettings> options)
    {
        _jwtPrivateKey = options.Value.JwtPrivateKey;

        GenerateKeys();

        if (signingCredentials == null || hmacKey == null)
        {
            throw new Exception("Key generator fail", new InvalidOperationException());
        }
    }

    public SymmetricSecurityKey GetSecurityKey()
    {
        return hmacKey;
    }

    public SigningCredentials GetSigningCredentials()
    {
        return signingCredentials!;
    }

    private void GenerateKeys()
    {
        try
        {
            var keyBytes = Encoding.UTF8.GetBytes(_jwtPrivateKey);

            hmacKey = new SymmetricSecurityKey(keyBytes);

            signingCredentials = new SigningCredentials(hmacKey, SecurityAlgorithms.HmacSha256);
        }
        catch (Exception ex)
        {
            throw new Exception("Couldn't generate symmetric " +
                "secutiry keys or signing credentials", ex);
        }
    }
}
