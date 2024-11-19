using Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.ControllerAggregate.Application
{
    public class ControllerAggregate(IControllerRepository repository) : IControllerAggregate
    {
        public List<ControllerSimpleResponse> GetControllers() => repository.GetControllers();
    }
}
