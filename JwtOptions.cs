namespace DiscordOauth;

public class JwtOptions
{
    public required string RsaPrivateKeyLocation { get; set; }
    public required string RsaPublicKeyLocation { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
}
