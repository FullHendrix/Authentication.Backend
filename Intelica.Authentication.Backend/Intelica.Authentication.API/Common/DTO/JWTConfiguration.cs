namespace Intelica.Authentication.API.Common.DTO
{
    public record JWTConfiguration
    {
        public string Key { get; init; }
    }
    public record Access(bool C, bool U, bool D);
}