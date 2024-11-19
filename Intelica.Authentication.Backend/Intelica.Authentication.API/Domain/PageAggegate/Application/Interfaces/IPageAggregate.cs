using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.PageAggegate.Application.Interfaces
{
    public interface IPageAggregate
    {
        List<ControllerSimpleResponse> FindControllersByPageRoot(string pageRoot);
    }
}
