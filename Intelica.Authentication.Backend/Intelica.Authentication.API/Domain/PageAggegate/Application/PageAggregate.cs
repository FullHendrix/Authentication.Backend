using Intelica.Authentication.API.Domain.PageAggegate.Application.Interfaces;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.PageAggegate.Application
{
    public class PageAggregate(IPageRepository repository) : IPageAggregate
    {
        public List<ControllerSimpleResponse> FindControllersByPageRoot(string pageRoot) => repository.FindControllersByPageRoot(pageRoot); 
    }
}
