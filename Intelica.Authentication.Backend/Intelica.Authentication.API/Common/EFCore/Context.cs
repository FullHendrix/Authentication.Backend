using Intelica.Authentication.API.Common.EFCore.Configuration;
using Intelica.Authentication.API.Domain.AuthenticationAggregate.Domain;
using Intelica.Authentication.API.Domain.BusinessUserAggregate.Domain;
using Intelica.Authentication.API.Domain.ClientAggregate.Domain;
using Intelica.Authentication.API.Domain.ControllerAggregate.Domain;
using Intelica.Authentication.API.Domain.PageAggegate.Domain;
using Intelica.Authentication.API.Domain.ProfileAggregate.Domain;
using Microsoft.EntityFrameworkCore;
namespace Intelica.Authentication.Domain.Common.EFCore
{
    public class Context(DbContextOptions<Context> options) : DbContext(options)
	{
		public DbSet<BusinessUser> BusinessUsers { get; set; }
        public DbSet<BusinessUserPage> BusinessUserPages { get; set; }
        public DbSet<Client> Clients { get; set; }
        public DbSet<Page> Pages { get; set; }
        public DbSet<PageController> PageController { get; set; }
        public DbSet<AccessInformation> AccessInformation { get; set; }
        public DbSet<Profile> Profiles { get; set; }
        public DbSet<Controller> Controllers { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.ApplyConfiguration(new ClientConfiguration());
            modelBuilder.ApplyConfiguration(new BusinessUserConfiguration());
            modelBuilder.ApplyConfiguration(new BusinessUserPageConfiguration());
            modelBuilder.ApplyConfiguration(new ClientConfiguration());
            modelBuilder.ApplyConfiguration(new PageConfiguration());
            modelBuilder.ApplyConfiguration(new PageControllerConfiguration());
            modelBuilder.ApplyConfiguration(new AccessInformationConfiguration());
            modelBuilder.ApplyConfiguration(new ProfileConfiguration());
            modelBuilder.ApplyConfiguration(new ControllerConfiguration());
        }
	}
}