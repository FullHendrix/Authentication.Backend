using Intelica.Authentication.API.Common.DTO;
using Intelica.Authentication.API.Common.Encriptation;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.DTO;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Domain;
using Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.PageAggegate.Application.Interfaces;
using Intelica.Infrastructure.Library.Cache.Interface;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
namespace Intelica.Authentication.API.Domain.AuthenticationAggregate.Application
{
    public class AuthenticatorAggregate(IGenericCache genericCache, IGenericRSA genericRSA, IClientAggregate client, IAuthenticationRepository repository,
    IOptionsSnapshot<JWTConfiguration> jwtConfiguration, IOptionsSnapshot<RSAConfiguration> rsaConfiguration, IControllerAggregate controlllerAggregate, IPageAggregate pageAggregate) : IAuthenticatorAggregate
    {
        public AuthenticationResponse ValidateAuthentication(AuthenticationQuery authenticationQuery, string ip)
        {
            if (!client.IsValid(authenticationQuery.ClientID, authenticationQuery.CallBack)) return new AuthenticationResponse("", "", false, false, null);
            var businessUser = ValidateCredentials(authenticationQuery.BusinessUserEmail, authenticationQuery.BusinessUserPassword, authenticationQuery.PublicKey);
            if (businessUser == null) return new AuthenticationResponse("", "", false, false, null);
            var token = GenerateToken(businessUser, ip, authenticationQuery.ClientID, "0");
            var refreshToken = GenerateRefreshToken(businessUser.BusinessUserID, ip);
            AuthenticationData autheticationData = new(businessUser.BusinessUserName, businessUser.BusinessUserEmail, businessUser.BusinessUserID,
            businessUser.BusinessUserProfile);
            return new AuthenticationResponse(token, refreshToken, true, businessUser.BusinessUserFirstLogin, autheticationData);
        }
        public AuthenticationLocalResponse ValidateAuthenticationInternal(AuthenticationInternalQuery authenticationLocalQuery, string ip)
        {
            if (!client.IsValid(authenticationLocalQuery.ClientID, null)) return new AuthenticationLocalResponse("", false);
            if (!rsaConfiguration.Value.PrivateKey.Equals(authenticationLocalQuery.PrivateKey)) return new AuthenticationLocalResponse("", false);
            var businessUser = repository.Find(authenticationLocalQuery.BusinessUserID);
            if (businessUser == null) return new AuthenticationLocalResponse("", false);
            var token = GenerateToken(businessUser, ip, authenticationLocalQuery.ClientID, "1");
            return new AuthenticationLocalResponse(token, true);
        }
        public ValidateTokenResponse ValidateToken(string token, Guid refreshToken, string businessUserEmail, string clientID, string ip, string pageRoot, string controller, string httpVerb)
        {
            if (token.Contains("Bearer")) token = token.Replace("Bearer ", "");
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtConfiguration.Value.Key);
            bool Expired = true; bool Unauthorized = true; string NewToken = ""; bool IsInternal = false;
            var generalControllers = controlllerAggregate.GetControllers();
            try
            {
                var jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

                IPrincipal principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                Expired = false;
                IsInternal = jwtSecurityToken.Claims.Any(x => x.Type.Equals("internal"));

                if (string.IsNullOrEmpty(pageRoot) && (generalControllers.Any(d => d.controllerName.Equals(controller, StringComparison.OrdinalIgnoreCase)) || string.IsNullOrEmpty(controller))) Unauthorized = false;
                else
                {
                    var controllersbyPage = pageAggregate.FindControllersByPageRoot(pageRoot);
                    var accessControllers = generalControllers.Concat(controllersbyPage).ToList();
                    var accessClaim = jwtSecurityToken.Claims.SingleOrDefault(x => x.Type.ToUpper().Equals(pageRoot.ToUpper()));
                    
                    if (accessClaim != null)
                    {
                        var access = JsonSerializer.Deserialize<Access>(accessClaim.Value) ?? new(false, false, false);
                        if (httpVerb.Equals("GET") ||
                        (httpVerb.Equals("POST") && access.C) ||
                        (httpVerb.Equals("DELETE") && access.D) ||
                        ((httpVerb.Equals("PUT") || httpVerb.Equals("PATCH")) && access.U))
                            Unauthorized = false;
                    }
                    if (!string.IsNullOrEmpty(controller) && !accessControllers.Any(d => d.controllerName.Equals(controller, StringComparison.OrdinalIgnoreCase))) Unauthorized = true;
                } 
            }
            catch
            {
                //Refresh token
                if (!IsInternal)
                {
                    var accesInformation = repository.FindAccessInformation(refreshToken);
                    if (accesInformation != null)
                        //if (DateTime.Now <= accesInformation.ExpirationDate && accesInformation.IP.Equals(ip))
                        if (DateTime.Now <= accesInformation.ExpirationDate)
                        {
                            var businessUser = repository.FindByEmail(businessUserEmail);
                            if (businessUser != null)
                            {
                                Expired = false;
                                NewToken = GenerateToken(businessUser, ip, clientID, "0");
                                var businessUserPage = (businessUser.BusinessUserPages ?? []).SingleOrDefault(x => x.PageRoot.ToUpper().Equals(pageRoot.ToUpper()));
                                if (businessUserPage != null)
                                {
                                    if (httpVerb.Equals("GET") ||
                                    (httpVerb.Equals("POST") && businessUserPage.CanCreate) ||
                                    (httpVerb.Equals("DELETE") && businessUserPage.CanDelete) ||
                                    ((httpVerb.Equals("PUT") || httpVerb.Equals("PATCH")) && businessUserPage.CanUpdate))
                                        Unauthorized = false;
                                }

                                if (string.IsNullOrEmpty(pageRoot) && (generalControllers.Any(d => d.controllerName.Equals(controller, StringComparison.OrdinalIgnoreCase)) || string.IsNullOrEmpty(controller))) Unauthorized = false;
                                else
                                {
                                    var controllersbyPage = pageAggregate.FindControllersByPageRoot(pageRoot);
                                    var accessControllers = generalControllers.Concat(controllersbyPage).ToList();
                                    if (!string.IsNullOrEmpty(controller) && !accessControllers.Any(d => d.controllerName.Equals(controller, StringComparison.OrdinalIgnoreCase))) Unauthorized = true;
                                }
                            }
                        }
                }
            }

            return new ValidateTokenResponse(Expired, Unauthorized, NewToken);
        }
        public ValidateTokenResponse ValidateTokenInternal(string token, Guid businessUserID, string clientID)
        {
            if (token.Contains("Bearer")) token = token.Replace("Bearer ", "");
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtConfiguration.Value.Key);
            bool Expired = true; bool Unauthorized = true; string NewToken = "";
            try
            {
                IPrincipal principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                Expired = false;
                Unauthorized = false;
            }
            catch
            {
                return new ValidateTokenResponse(Expired, Unauthorized, NewToken);
            }
            return new ValidateTokenResponse(Expired, Unauthorized, NewToken);
        }
        #region Private
        private string GenerateToken(BussinesUserResponse businessUserResponse, string ip, string clientID, string isInternal)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.Value.Key));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); 

            List<Claim> claims = [];
            foreach (var businessUserPage in businessUserResponse.BusinessUserPages ?? [])
            {
                var accessLevel = JsonSerializer.Serialize(new Access(businessUserPage.CanCreate, businessUserPage.CanUpdate, businessUserPage.CanDelete));
                claims.Add(new(businessUserPage.PageRoot, accessLevel));
            }
            claims.Add(new("preferred_username", businessUserResponse.BusinessUserName));
            claims.Add(new("sub", businessUserResponse.BusinessUserID.ToString()));
            claims.Add(new("email", businessUserResponse.BusinessUserEmail));
            if (isInternal == "1") claims.Add(new("internal", isInternal));
            var token = new JwtSecurityToken(
                issuer: "auth.intelica.com",
                audience: clientID,
                claims: claims,
                expires: DateTime.Now.AddMinutes(businessUserResponse.BusinessUserPages == null ? 10 : 1),
                signingCredentials: credentials
            );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private string GenerateRefreshToken(Guid businessUserID, string ip)
        {
            var accesInformation = new AccessInformation(businessUserID, ip, DateTime.Now.AddMinutes(720));
            repository.CreateAccessInformation(accesInformation);
            repository.SaveChanges();
            return accesInformation.AccessInformationID.ToString();
        }
        private BussinesUserResponse? ValidateCredentials(string businessUserEmail, string businessUserPassword, string publicKey)
        {
            var privateKey = genericCache.Get<string>(publicKey);
            if (privateKey == null) { return null; }
            string businessUserPasswordDecripted = genericRSA.Decript(privateKey, businessUserPassword);
            var bussinesUser = repository.FindByEmail(businessUserEmail);
            if (bussinesUser != null)
            {
                string businessUserResponsePasswordDecripted = genericRSA.Decript(rsaConfiguration.Value.PrivateKey, bussinesUser.BusinessUserPassword);
                if (businessUserPasswordDecripted == businessUserResponsePasswordDecripted) return bussinesUser;
            }
            return null;
        }
        #endregion
        public AuthenticationMailResponse ValidateAuthenticationMail(AuthenticationMailQuery authenticationMailQuery)
        {
            var businessUser = repository.FindByEmail(authenticationMailQuery.BusinessUserEmail);
            if (businessUser == null) return new AuthenticationMailResponse(false, "");
            Random rnd = new Random();
            var codeRandom = "U" + rnd.Next(1000, 9999).ToString();
            return new AuthenticationMailResponse(true, codeRandom); ;
        }
        public AuthenticationSendMailResponse ValidateAuthenticationSendMail(AuthenticationSendMailQuery authenticationSendMailQuery, string ip)
        {
            if (!client.IsValid(authenticationSendMailQuery.ClientID, authenticationSendMailQuery.CallBack)) return new AuthenticationSendMailResponse("", "", false);
            var businessUser = repository.FindByEmail(authenticationSendMailQuery.BusinessUserEmail);
            if (businessUser == null) return new AuthenticationSendMailResponse("", "", false);
            var token = GenerateToken(businessUser, ip, authenticationSendMailQuery.ClientID, "0");
            var refreshToken = GenerateRefreshToken(businessUser.BusinessUserID, ip);
            return new AuthenticationSendMailResponse(token, refreshToken, true); ;
        }
    }
}