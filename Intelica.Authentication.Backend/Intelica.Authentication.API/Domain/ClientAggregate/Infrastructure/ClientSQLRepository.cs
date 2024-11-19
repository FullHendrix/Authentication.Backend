using Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.ClientAggregate.Domain;
using Intelica.Authentication.Domain.Common.EFCore;
namespace Intelica.Authentication.API.Domain.ClientAggregate.Infrastructure
{
    public class ClientSQLRepository(Context context) : IClientRepository
    {
        public Client? Find(string clientID)
        {
            var row = context.Clients.SingleOrDefault(x => x.ClientID.Equals(clientID));
            return row;
        }
    }
}