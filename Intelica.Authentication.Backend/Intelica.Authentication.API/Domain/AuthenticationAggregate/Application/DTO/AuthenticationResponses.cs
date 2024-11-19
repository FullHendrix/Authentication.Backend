using Intelica.Authentication.API.Common.DTO;
using static Intelica.Authentication.API.Domain.ControllerAggregate.Application.DTO.ControllerResponses;

namespace Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.DTO
{
    public record AuthenticationResponse(string JwtToken, string RefreshToken, bool valid, bool BusinessUserFirstLogin, AuthenticationData? AuthenticationData);
    public record AuthenticationData(string BusinessUserName, string BusinessUserEmail, Guid BusinessUserID, string BusinessUserProfile);
    public record AuthenticationLocalResponse(string JwtToken, bool valid);
    public record PageControllerResponse(Guid ControllerID, string ControllerName);
    public record BussinesUserResponse(Guid BusinessUserID, string BusinessUserName, string BusinessUserEmail, string BusinessUserPassword,
    string BusinessUserProfile, bool BusinessUserFirstLogin, List<BusinessUserPageResponse>? BusinessUserPages);
    public record BusinessUserPageResponse(Guid PageID, string PageRoot, bool CanUpdate, bool CanCreate, bool CanDelete, List<ControllerSimpleResponse> PageControllers);
    public record ValidateTokenResponse(bool Expired, bool Unauthorized, string NewToken);
    public record AuthenticationMailResponse(bool valid, string Code);
    public record AuthenticationSendMailResponse(string JwtToken, string RefreshToken, bool valid);
}