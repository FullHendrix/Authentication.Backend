using System.IdentityModel.Tokens.Jwt;
namespace Intelica.Authentication.API.Extensions
{
    public class UserDataRetriever
    {
        public Guid BussinesUserID { get; private set; }
        public Guid MenuUserID { get; set; }
        public string BussinesUserName { get; private set; }
        public string BussinesUserEmail { get; private set; }
        public UserDataRetriever(string autorizationHeader)
        {
            if (autorizationHeader.Contains("Bearer")) autorizationHeader = autorizationHeader.Replace("Bearer ", "");
            var jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(autorizationHeader);
            BussinesUserName = jwtSecurityToken.Claims.Single(x => x.Type.Equals("preferred_username")).Value;
            BussinesUserID = Guid.Parse(jwtSecurityToken.Claims.Single(x => x.Type.Equals("sub")).Value);
            BussinesUserEmail = jwtSecurityToken.Claims.Single(x => x.Type.Equals("email")).Value;
        }
    }
}