using AspNetCore.Identity.Database;
using Microsoft.EntityFrameworkCore;

namespace AspNetCore.Identity.Extensions;



internal static class MigrationExtensions
{
    public static void ApplyMigrations(this IApplicationBuilder app)
    {
        using IServiceScope scope = app.ApplicationServices.CreateScope();
        using ApplicationDbContext context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate();
    }
    
}
