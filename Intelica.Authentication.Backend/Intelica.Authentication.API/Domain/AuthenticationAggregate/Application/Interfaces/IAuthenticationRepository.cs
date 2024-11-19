using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.DTO;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Domain;
namespace Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.Interfaces
{
    public interface IAuthenticationRepository
    {
        BussinesUserResponse? FindByEmail(string businessUserEmail);
        BussinesUserResponse? Find(Guid businessUserID);
        void CreateAccessInformation(AccessInformation accessInformation);
        AccessInformation? FindAccessInformation(Guid businessUserID);
        void SaveChanges();
    }
}