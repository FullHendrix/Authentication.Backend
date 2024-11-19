namespace Intelica.Authentication.API.Common.DTO
{
    public record RSAConfiguration
    {
        public string PrivateKey { get; init; }
        public string PublicKey { get; init; }
    }
}