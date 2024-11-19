using Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces;
namespace Intelica.Authentication.API.Domain.ClientAggregate.Application
{
    public class ClientAggregate(IClientRepository repository) : IClientAggregate
    {
        public bool IsValid(string clientID, string? callBack)
        {
            var client = repository.Find(clientID);
            if(client ==  null) { return false; }
            return client.IsValid(callBack);
        }
    }
}