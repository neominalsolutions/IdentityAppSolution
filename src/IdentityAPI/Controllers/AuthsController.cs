using Azure.Core;
using IdentityAPI.Dtos;
using IdentityAPI.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;

namespace IdentityAPI.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthsController : ControllerBase
  {
    private readonly IAccessTokenService accessTokenService;

    public AuthsController(IAccessTokenService accessTokenService)
    {
      this.accessTokenService = accessTokenService;
    }


    [HttpPost("token")]
    //[EnableRateLimiting("findUsers")]
    //[DisableRateLimiting]
    public async Task<IActionResult> CreateTokenAsync([FromBody] TokenRequestDto tokenRequest)
    {


      if (tokenRequest.Email.StartsWith("test") && tokenRequest.Password == "12345")
      {
        var claims = new List<Claim>();
        claims.Add(new Claim("UserId",Guid.NewGuid().ToString()));
        claims.Add(new Claim("Email", tokenRequest.Email));
        claims.Add(new Claim(ClaimTypes.Role, "admin"));
        claims.Add(new Claim(ClaimTypes.Role, "manager"));
        claims.Add(new Claim("User", "Insert"));
        claims.Add(new Claim("User", "Update"));
        claims.Add(new Claim("User", "Approve"));
        claims.Add(new Claim("User", "Delete"));

        var identity = new ClaimsIdentity(claims);

        var response = this.accessTokenService.CreateAccessToken(identity);

        var data = await Task.FromResult<TokenResponseDto>(response);

 



        return Ok(data);

      }

    

      return BadRequest();
   

    }
  }
}
