using Intelica.Authentication.API.Extensions;
using Intelica.Authentication.API.Middleware;
using Intelica.Authentication.Domain.Common.EFCore;
using Microsoft.EntityFrameworkCore;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "";
if (environment == "Docker") builder.Configuration.AddJsonFile("appsettings/appsettings.docker.json", optional: false, reloadOnChange: true);
else builder.Configuration.AddJsonFile("appsettings/appsettings.json", optional: false, reloadOnChange: true);
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: "local", policy =>
    {
        policy.AllowAnyHeader();
        policy.AllowAnyMethod();
        policy.AllowAnyOrigin();
    });
});
DIExtension.AddConfigurations(builder.Services);
OptionsExtension.AddConfiguration(builder.Services, builder.Configuration);
builder.Services.AddMemoryCache();
builder.Services.AddDbContext<Context>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("Security"),
        sqlServerOptionsAction: builder =>
        {
            builder.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(5),
                errorNumbersToAdd: null);
        });
});
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});
var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthorization();
app.UseCors("local");
app.UseMiddleware<ExceptionMiddleware>();
app.MapControllers();
app.Run();