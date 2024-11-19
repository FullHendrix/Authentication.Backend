using Intelica.Authentication.API.Domain.PageAggegate.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace Intelica.Authentication.API.Common.EFCore.Configuration
{
    public class PageConfiguration : IEntityTypeConfiguration<Page>
    {
        public void Configure(EntityTypeBuilder<Page> builder)
        {
            builder.ToTable(nameof(Page)).HasKey(x => x.PageID);
            builder.HasMany(x => x.PageControllers).WithOne(x => x.Page).HasForeignKey(x => x.PageID);
        }
    }
    public class PageControllerConfiguration : IEntityTypeConfiguration<PageController>
    {
        public void Configure(EntityTypeBuilder<PageController> builder)
        {
            builder.ToTable(nameof(PageController)).HasKey(x => x.PageControllerID);
        }
    }
}