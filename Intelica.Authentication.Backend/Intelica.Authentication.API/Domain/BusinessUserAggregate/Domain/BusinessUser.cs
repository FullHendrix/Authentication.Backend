namespace Intelica.Authentication.API.Domain.BusinessUserAggregate.Domain
{
    public class BusinessUser
    {
        public Guid BusinessUserID { get; private set; }
        public string BusinessUserName { get; private set; }
        public string BusinessUserFirstName { get; private set; }
        public string BusinessUserLastName { get; private set; }
        public string BusinessUserEmail { get; private set; }
        public string BusinessUserPassword { get; private set; }
        public Guid ProfileID { get; private set; }
        public bool BusinessUserActive { get; private set; }
        public bool BusinessUserFirstLogin { get; private set; }
        public List<BusinessUserPage> BusinessUserPages { get; private set; }
        public BusinessUser(){}
    }
}