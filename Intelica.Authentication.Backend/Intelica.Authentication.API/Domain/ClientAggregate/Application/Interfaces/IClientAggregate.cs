namespace Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces
{
    public interface IClientAggregate
    {
        bool IsValid(string clientID, string? callBack);
    }
}