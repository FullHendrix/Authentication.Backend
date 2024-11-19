using Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.ControllerAggregate.Domain;
using Intelica.Authentication.Domain.Common.EFCore;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.ControllerAggregate.Infrastructure
{
    public class ControllerSQLServerRepository(Context context) : IControllerRepository
    {
        public List<ControllerSimpleResponse> GetControllers()
        {
            var query = (from controller in context.Controllers
                         where controller.IsGeneral == true
                         select new ControllerSimpleResponse(controller.ControllerName)).ToList();

            return query;
        }
    }
}

