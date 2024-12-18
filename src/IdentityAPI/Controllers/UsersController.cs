using IdentityAPI.Dtos;
using IdentityAPI.Filters;
using IdentityAPI.Identity.Models;
using IdentityAPI.Requests;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityAPI.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class UsersController : ControllerBase
  {
    private readonly UserManager<AppUser> userManager;
    private readonly RoleManager<AppRole> roleManager;

    public UsersController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
    {
      this.userManager = userManager;
      this.roleManager = roleManager;
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = "TGSJWTBearer")]
    public async Task<IActionResult> CreateUser([FromBody] UserRegisterRequest registerRequest)
    {

      var user = new AppUser
      {
        UserName = registerRequest.Name,
        Email = registerRequest.Email
      };

      await userManager.CreateAsync(user, registerRequest.Password);

    
      var dbRole = await roleManager.FindByNameAsync(registerRequest.RoleName);

      if(dbRole == null)
      {
        var role = new AppRole
        {
          Name = registerRequest.RoleName
        };

        var result = await roleManager.CreateAsync(role);

        if(result.Succeeded)
        {
          var _user = await userManager.FindByEmailAsync(user.Email);
          ArgumentNullException.ThrowIfNull(_user);
          // user Role tablosuna kayıt at.
          await userManager.AddToRoleAsync(_user, role.Name);
        }


       

      }


      return Ok();
    }

    [HttpGet("findClaims/{email}")]
    //[Authorize(Roles = "SuperVisor")]
    //[PermissionFilter("User","Create")]
    // [Authorize(Policy = "UserPermissionByAdmin")]
    // User-Agent göre aynı tarayıcıdan gelirse cache yapar.
    //[ResponseCache(VaryByHeader = "User-Agent", Duration = 30)]
    [ResponseCache(VaryByHeader = "User-Agent", CacheProfileName = "CacheProfile3")]
    public async Task<IActionResult> FindUserRoleClaims(string email)
    {

      //await HttpContext.AuthenticateAsync();
      // string userId = HttpContext.User.GetLoggedInUserId();


           var user = await userManager.FindByEmailAsync(email);
      ArgumentNullException.ThrowIfNull(user);

      List<ClaimDto> claims = []; // C# 12 sonrası

      var userClaims = await userManager.GetClaimsAsync(user);
      claims.AddRange(userClaims.Select(a=> new ClaimDto(a.Value,a.Type)));

      var userRoles = await userManager.GetRolesAsync(user);

      // Linq foreach async ifadelerde taskı beklemeden gidiyor.
      // normal foreach ile ilerleyelim.

      foreach (var roleName in userRoles)
      {
        var role = await roleManager.FindByNameAsync(roleName);
        ArgumentNullException.ThrowIfNull(role);
        var roleClaims = await roleManager.GetClaimsAsync(role);

        claims.AddRange(roleClaims.Select(a=> new ClaimDto(a.Value,a.Type)));
      }



      return Ok(new {user =  user, claims = claims});
    }
  }
}
