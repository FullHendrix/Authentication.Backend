using Intelica.Authentication.API.Common.Encriptation;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Infrastructure;
using Intelica.Authentication.API.Domain.ClientAggregate.Application;
using Intelica.Authentication.API.Domain.ClientAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.ClientAggregate.Infrastructure;
using Intelica.Authentication.API.Domain.ControllerAggregate.Application;
using Intelica.Authentication.API.Domain.ControllerAggregate.Application.Interfaces;
using Intelica.Authentication.API.Domain.ControllerAggregate.Infrastructure;
using Intelica.Authentication.API.Domain.PageAggegate.Application;
using Intelica.Authentication.API.Domain.PageAggegate.Application.Interfaces;
using Intelica.Authentication.API.Domain.PageAggegate.Infrastructure;
using Intelica.Infrastructure.Library.Cache;
using Intelica.Infrastructure.Library.Cache.Interface;
using Intelica.Infrastructure.Library.Email;
using Intelica.Infrastructure.Library.Email.Interface;
using Intelica.Infrastructure.Library.GenericApi;
using Intelica.Infrastructure.Library.GenericApi.Interface;
using Intelica.Infrastructure.Library.Log;
using Intelica.Infrastructure.Library.Log.Interrfaces;
using Intelica.Infrastructure.Library.MessageBroker;
using Intelica.Infrastructure.Library.MessageBroker.Interface;
using Intelica.Infrastructure.Library.Storage;
using Intelica.Infrastructure.Library.Storage.Interface;
using Intelica.Infrastructure.Library.WebSocket;
using Intelica.Infrastructure.Library.WebSocket.Interface;
namespace Intelica.Authentication.API.Extensions
{
    public static class DIExtension
    {
        public static IServiceCollection AddConfigurations(this IServiceCollection services)
        {
            services.AddSingleton<ILog, StandartOuputLog>();
            services.AddSingleton<IGenericCache, InMemoryCache>();
            services.AddTransient<IWebSocket, WebSocketSignalR>();
            services.AddTransient<IMessageBroker, MessageBrokerAWSSQS>();
            services.AddTransient<IGenericApiProxy, GenericApiProxy>();
            services.AddTransient<IGenericRSA, GenericRSA>();
            services.AddTransient<IAuthenticatorAggregate, AuthenticatorAggregate>();
            services.AddTransient<IAuthenticationRepository, AuthenticationSQLServerRepository>();
            services.AddTransient<IClientAggregate, ClientAggregate>();
            services.AddTransient<IClientRepository, ClientSQLRepository>();
            services.AddTransient<IEmailNotification, EmailNotificationSMTP>();
            services.AddScoped<IStorage, StorageAWSS3>();
            services.AddTransient<IControllerAggregate, ControllerAggregate>();
            services.AddTransient<IControllerRepository, ControllerSQLServerRepository>();
            services.AddTransient<IPageAggregate, PageAggregate>();
            services.AddTransient<IPageRepository, PageSQLServerRepository>();
            return services;
        }
    }
}