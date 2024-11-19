using Intelica.Authentication.API.Domain.AuthenticationAggregate.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace Intelica.Authentication.API.Common.EFCore.Configuration
{
    public class AccessInformationConfiguration : IEntityTypeConfiguration<AccessInformation>
    {
        public void Configure(EntityTypeBuilder<AccessInformation> builder)
        {
            builder.ToTable(nameof(AccessInformation)).HasKey(x => x.AccessInformationID);
        }
    }
}