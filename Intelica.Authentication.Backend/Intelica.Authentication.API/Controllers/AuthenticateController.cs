using Intelica.Authentication.API.Common.Encriptation;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.DTO;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.Interfaces;
using Intelica.Infrastructure.Library.Cache.Interface;
using Intelica.Infrastructure.Library.Email.DTO;
using Intelica.Infrastructure.Library.Email.Interface;
using Intelica.Authentication.API.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
namespace Intelica.Authentication.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticateController(IGenericRSA customRSA, IAuthenticatorAggregate authenticator, IGenericCache cache, IEmailNotification emailNotification) : Controller
    {
        [HttpGet]
        public IActionResult GetPublicKey()
        {
            var keyValue = customRSA.GetKeys();
            return Ok(new { publicKey = keyValue.Key });
        }
        [HttpPost]
        public IActionResult ValidateAuthentication(AuthenticationQuery authenticationQuery)
        {
            var ip = Request.Host.Value;
            var response = authenticator.ValidateAuthentication(authenticationQuery, ip);
            var cookieOptions = new CookieOptions
            {
                HttpOnly = false,
                Expires = DateTime.Now.AddDays(1),
                Secure = true, // Es necesario para SameSite=None
                SameSite = SameSiteMode.None, // Permitir envío entre diferentes sitios
            };
            Response.Cookies.Append("token", response.JwtToken, cookieOptions);
            Response.Cookies.Append("refresToken", response.RefreshToken, cookieOptions);
            Response.Cookies.Append("data", JsonSerializer.Serialize(response.AuthenticationData), cookieOptions);
            return Ok(response);
        }
        [HttpPost]
        [Route("ValidateAuthenticationInternal")]
        public IActionResult ValidateAuthenticationInternal(AuthenticationInternalQuery authenticationLocalQuery)
        {
            var ip = Request.Host.Value;
            var response = authenticator.ValidateAuthenticationInternal(authenticationLocalQuery, ip);
            return Ok(response);
        }
        [HttpPost]
        [Route("ValidateToken")]
        public IActionResult ValidateToken(ValidateTokenQuery validateTokenQuery)
        {
            var userData = new UserDataRetriever(validateTokenQuery.Token);
            var response = authenticator.ValidateToken(validateTokenQuery.Token, validateTokenQuery.RefreshToken, userData.BussinesUserEmail,
            validateTokenQuery.ClientID, validateTokenQuery.Ip, validateTokenQuery.PageRoot, validateTokenQuery.Controller, validateTokenQuery.HttpVerb);
            return Ok(response);
        }
        [HttpPost]
        [Route("AuthenticationMail")]
        public async Task<IActionResult> AuthenticationMail(AuthenticationMailQuery authenticationMailQuery)
        {
            var ip = Request.Host.Value;
            var response = authenticator.ValidateAuthenticationMail(authenticationMailQuery);
            if (response.valid)
            {
                string userCodeKey = $"UserCode_{response.Code}";
                var timeExpired = TimeSpan.FromMinutes(10);
                var ParamMail = new SendEmailInformation
                {
                    To = authenticationMailQuery.BusinessUserEmail,
                    Subject = "Token code: " + response.Code
                };
                string _body = "Your authentication token code is: <b>" + response.Code + "</b>";
                ParamMail.Body = _body;
                cache.Set(response.Code, userCodeKey, timeExpired);
                await emailNotification.Send(ParamMail);
            }

            return Ok(response);
        }
        [HttpPost]
        [Route("AuthenticationSendCode")]
        public IActionResult AuthenticationSendCode(AuthenticationSendMailQuery authenticationSendMailQuery)
        {
            string userCodeKey = $"UserCode_{authenticationSendMailQuery.Code}";
            var codeTemp = cache.Get<string>(userCodeKey);
            if (codeTemp is null) return Ok(new AuthenticationSendMailResponse("", "", false));
            if (codeTemp != authenticationSendMailQuery.Code) return Ok(new AuthenticationSendMailResponse("", "", false));
            var ip = Request.Host.Value;
            var response = authenticator.ValidateAuthenticationSendMail(authenticationSendMailQuery, ip);
            var cookieOptions = new CookieOptions
            {
                HttpOnly = false,
                Expires = DateTime.Now.AddDays(1),
                Secure = true, // Es necesario para SameSite=None
                SameSite = SameSiteMode.None, // Permitir envío entre diferentes sitios
            };
            Response.Cookies.Append("token", response.JwtToken, cookieOptions);
            Response.Cookies.Append("refresToken", response.RefreshToken, cookieOptions);
            cache.Clear(userCodeKey);
            return Ok(response);
        }
    }
}