using IdentityAPI.Dtos;
using System.Security.Claims;

namespace IdentityAPI.Services
{
  public interface IAccessTokenService
  {
    TokenResponseDto CreateAccessToken(ClaimsIdentity identity);
  }
}
