using Intelica.Authentication.API.Domain.BusinessUserAggregate.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace Intelica.Authentication.API.Common.EFCore.Configuration
{
    internal class BusinessUserConfiguration : IEntityTypeConfiguration<BusinessUser>
    {
        public void Configure(EntityTypeBuilder<BusinessUser> builder)
        {
            builder.ToTable(nameof(BusinessUser)).HasKey(x => x.BusinessUserID);
            builder.HasMany(x => x.BusinessUserPages).WithOne(x => x.BusinessUser).HasForeignKey(x => x.BusinessUserID);
        }
    }
    internal class BusinessUserPageConfiguration : IEntityTypeConfiguration<BusinessUserPage>
    {
        public void Configure(EntityTypeBuilder<BusinessUserPage> builder)
        {
            builder.ToTable(nameof(BusinessUserPage)).HasKey(x => x.BusinessUserPageID);
        }
    }
}
