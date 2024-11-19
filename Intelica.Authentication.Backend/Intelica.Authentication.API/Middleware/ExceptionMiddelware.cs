using Intelica.Infrastructure.Library.Log.DTO;
using Intelica.Infrastructure.Library.Log.Interrfaces;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel;
using System.Text.Json;
namespace Intelica.Authentication.API.Middleware
{
	public class ExceptionMiddleware(RequestDelegate next, ILog log)
	{
		private readonly string _environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Local";
		private static Task HandleGlobalExceptionAsync(HttpContext context, Guid processId, int StatusCode, string message, string error, string? innerError)
		{
			context.Response.ContentType = "application/json";
			context.Response.StatusCode = StatusCode;
			var result = new { message = $"{message} <br/> Codigo de seguimiento: <br/>  {processId}", error, innerError };
			return context.Response.WriteAsync(JsonSerializer.Serialize(result));
		}
		public async Task InvokeAsync(HttpContext context)
		{
			var processId = Guid.NewGuid();
			try
			{
				context.Request.Headers.Add("ProcessId", processId.ToString());
				log.Send(new BodyLog(Guid.NewGuid(), _environment, "Info", $"Inico de LLamada a controlador",
					 new
					 {
						 verb = context.Request.Method,
						 controller = context.Request.RouteValues["Controller"],
						 context.Request.Path
					 }));
				await next(context);
			}
			catch (SqlException ex)
			{
				var customMessage = "Ha ocurrido un error no controlado con la base de datos.";
				if (ex.Number.Equals(53)) await HandleGlobalExceptionAsync(context, processId, 500, "Se ha generado un error al intentar conectar con la base de datos.", ex.Message, ex.InnerException?.Message);
				if (ex.Number.Equals(-2)) await HandleGlobalExceptionAsync(context, processId, 408, "Se ha superado el tiempo de espera con la base de datos.", ex.Message, ex.InnerException?.Message);
				else await HandleGlobalExceptionAsync(context, processId, 500, customMessage, ex.Message, ex.InnerException?.Message);
				log.Send(new BodyLog(processId, _environment, "Error", customMessage, new { message = ex.Message, innerException = ex.InnerException?.Message }));
			}
			catch (DbUpdateException ex)
			{
				var customMessage = $"Se ha generado un error de consistencia en la base de datos.";
				await HandleGlobalExceptionAsync(context, processId, 500, customMessage, ex.Message, ex.InnerException?.Message);
				log.Send(new BodyLog(processId, _environment, "Error", customMessage, new { message = ex.Message, innerException = ex.InnerException?.Message }));
			}
			catch (WarningException ex)
			{
				await HandleGlobalExceptionAsync(context, processId, 400, ex.Message, ex.Message, ex.InnerException?.Message);
				log.Send(new BodyLog(processId, _environment, "Error", ex.Message, new { message = ex.Message, innerException = ex.InnerException?.Message }));
			}
			catch (SecurityTokenInvalidLifetimeException ex)
			{
				var customMessage = "No tiene acceso para acceder a este recurso.";
				await HandleGlobalExceptionAsync(context, processId, 403, customMessage, ex.Message, ex.InnerException?.Message);
				log.Send(new BodyLog(processId, _environment, "Error", customMessage, new { message = ex.Message, innerException = ex.InnerException?.Message }));
			}
			catch (Exception ex)
			{
				var customMessage = "Ha ocurrido un error no controlado con la aplicación.";
				await HandleGlobalExceptionAsync(context, processId, 500, customMessage, ex.Message, ex.InnerException?.Message);
				log.Send(new BodyLog(processId, _environment, "Error", customMessage, new { message = ex.Message, innerException = ex.InnerException?.Message }));
			}
		}
	}
}