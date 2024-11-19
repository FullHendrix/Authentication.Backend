using Intelica.Authentication.API.Domain.PageAggegate.Application.Interfaces;
using Intelica.Authentication.Domain.Common.EFCore;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.PageAggegate.Infrastructure
{
    public class PageSQLServerRepository(Context context) : IPageRepository
    {
        public List<ControllerSimpleResponse> FindControllersByPageRoot(string pageRoot)
        {
            var query = (from pageController in context.PageController 
                         join page in context.Pages on pageController.PageID equals page.PageID
                         join controller in context.Controllers on pageController.ControllerID equals controller.ControllerID
                         where page.PageRoot.Equals(pageRoot)
                         select new ControllerSimpleResponse(controller.ControllerName)).ToList(); 

            return query;
        }
    }
}
