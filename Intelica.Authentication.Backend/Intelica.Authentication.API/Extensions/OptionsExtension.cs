using Intelica.Authentication.API.Common.DTO;
using Intelica.Infrastructure.Library.Email.DTO;
using Intelica.Infrastructure.Library.MessageBroker.DTO;

namespace Intelica.Authentication.API.Extensions
{
    public static class OptionsExtension
    {
        public static void AddConfiguration(IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<JWTConfiguration>(configuration.GetSection("JWT"));
            services.Configure<RSAConfiguration>(configuration.GetSection("RSA"));
            services.Configure<SendEmailConfiguration>(configuration.GetSection("EmailSettings"));
            services.Configure<S3Configuration>(configuration.GetSection("AWS").GetSection("S3"));
        }
    }
}