using Microsoft.AspNetCore.Identity;

namespace IdentityAPI.Identity.Models
{
    public class AppUser : IdentityUser
    {
        public string? Description { get; set; }

    }
}
