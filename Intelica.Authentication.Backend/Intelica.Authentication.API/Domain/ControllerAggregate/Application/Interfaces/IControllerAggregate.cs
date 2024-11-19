using Intelica.Authentication.API.Domain.ControllerAggregate.Domain;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces
{
    public interface IControllerAggregate
    {
        List<ControllerSimpleResponse> GetControllers();
    }
}
