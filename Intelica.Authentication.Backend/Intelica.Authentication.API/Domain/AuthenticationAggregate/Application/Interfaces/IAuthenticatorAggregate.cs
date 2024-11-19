using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.DTO;
namespace Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.Interfaces
{
    public interface IAuthenticatorAggregate
    {
        AuthenticationResponse ValidateAuthentication(AuthenticationQuery authenticationQuery, string ip);
        AuthenticationLocalResponse ValidateAuthenticationInternal(AuthenticationInternalQuery authenticationLocalQuery, string ip);
        ValidateTokenResponse ValidateToken(string token, Guid refreshToken, string businessUserEmail, string clientID, string ip, string pageRoot, string controller, string httpVerb);
        AuthenticationMailResponse ValidateAuthenticationMail(AuthenticationMailQuery authenticationMailQuery);
        AuthenticationSendMailResponse ValidateAuthenticationSendMail(AuthenticationSendMailQuery authenticationSendMailQuery, string ip);
    }
}