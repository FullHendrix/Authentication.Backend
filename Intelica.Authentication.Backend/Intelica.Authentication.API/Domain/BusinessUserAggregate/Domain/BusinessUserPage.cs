namespace Intelica.Authentication.API.Domain.BusinessUserAggregate.Domain
{
    public class BusinessUserPage()
    {
        public Guid BusinessUserPageID { get; private set; }
        public Guid BusinessUserID { get; private set; }
        public Guid PageID { get; private set; }
        public bool BusinessUserPageCanUpdate { get; private set; }
        public bool BusinessUserPageCanCreate { get; private set; }
        public bool BusinessUserPageCanDelete { get; private set; }
        public bool BusinessUserPageActive { get; private set; }
        public BusinessUser BusinessUser { get; set; }
    }
}
