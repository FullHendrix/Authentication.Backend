using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces
{
    public interface IControllerRepository
    {
        List<ControllerSimpleResponse> GetControllers();
    }
}
