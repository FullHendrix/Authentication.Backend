namespace Intelica.Authentication.API.Domain.ControllerAggregate.Domain
{
    public class Controller
    {
        public Guid ControllerID { get; private set; }
        public string ControllerName { get; private set; }
        public bool IsGeneral { get; private set; }
        public bool ControllerActive { get; private set; }
    }
}