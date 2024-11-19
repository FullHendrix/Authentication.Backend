namespace Intelica.Authentication.API.Domain.ProfileAggregate.Domain
{
    public class Profile
    {
        public Guid ProfileID { get; private set; }
        public string ProfileName { get; private set; }
        public Profile(){}
    }
}