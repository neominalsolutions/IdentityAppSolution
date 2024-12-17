using IdentityAPI.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityAPI.Identity.Contexts
{
  public class AppIdentityDbContext:IdentityDbContext<AppUser,AppRole,string>
  {

        public AppIdentityDbContext(DbContextOptions<AppIdentityDbContext> opt):base(opt)
        {
            
        }

    protected override void OnModelCreating(ModelBuilder builder)
    {

      base.OnModelCreating(builder);

      builder.Entity<AppRole>().ToTable("Roles");
      builder.Entity<AppUser>().ToTable("Users");
      builder.Entity<IdentityUserClaim<string>>().ToTable("UserClaims");
      builder.Entity<IdentityUserRole<string>>().ToTable("RoleClaims");
      builder.Entity<IdentityUserRole<string>>().ToTable("UserRoles");
      builder.Entity<IdentityUserLogin<string>>().ToTable("UserLogins");

    
    }
  }
}
