namespace Intelica.Authentication.API.Domain.AuthenticationAggregate.Domain
{
    public class AccessInformation
    {
        public Guid AccessInformationID { get; private set; }
        public Guid BusinessUserID { get; private set; } 
        public string IP { get; private set; }
        public DateTime GenerationDate { get; private set; }
        public DateTime ExpirationDate { get; private set; } 
        public AccessInformation() { }
        public AccessInformation(Guid businessUserID, string ip, DateTime expirationDate)
        {
            AccessInformationID = Guid.NewGuid();
            BusinessUserID = businessUserID;
            IP = ip;
            GenerationDate = DateTime.Now;
            ExpirationDate = expirationDate;
        }
    }
}