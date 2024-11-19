namespace Intelica.Authentication.API.Domain.PageAggegate.Domain
{
    public class PageController
    {
        public Guid PageControllerID { get; private set; }
        public Guid PageID { get; private set; }
        public Guid ControllerID { get; private set; }
        public bool PageControllerActive { get; private set; }
        public Page Page { get; private set; }
    }
}