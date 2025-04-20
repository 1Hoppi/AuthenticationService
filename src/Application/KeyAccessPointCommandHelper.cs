using Authenticator;

public class KeyAccessPointCommandHelper
{
    private readonly IKeyProvider _keyProvider;

    public KeyAccessPointCommandHelper(IKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    public PublicKeyReply GetPublicKey()
    {
        return new PublicKeyReply()
        {
            Key = _keyProvider.GetPublicRsaSecurityKeyString()
        };
    }
}