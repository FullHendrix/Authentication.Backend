using Intelica.Authentication.API.Domain.ControllerAggregate.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace Intelica.Authentication.API.Common.EFCore.Configuration
{
    internal class ControllerConfiguration : IEntityTypeConfiguration<Controller>
    {
        public void Configure(EntityTypeBuilder<Controller> builder)
        {
            builder.ToTable(nameof(Controller)).HasKey(x => x.ControllerID);
        }
    }
}