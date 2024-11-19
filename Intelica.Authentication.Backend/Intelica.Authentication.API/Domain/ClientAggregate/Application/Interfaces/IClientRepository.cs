using Intelica.Authentication.API.Domain.ClientAggregate.Domain;
namespace Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces
{
    public interface IClientRepository
    {
        Client? Find( string clientID);
    }
}