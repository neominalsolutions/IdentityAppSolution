using System.Security.Claims;

namespace IdentityAPI
{

  // Login Olan UserId HttpContext okuma extension
  public static class ClaimsPrincipalExtensions
  {
    public static string GetLoggedInUserId(this ClaimsPrincipal principal)
    {
      if (principal == null)
        throw new ArgumentNullException(nameof(principal));

      var loggedInUserId = principal.FindFirstValue("UserId");

      ArgumentNullException.ThrowIfNull(loggedInUserId);

      return loggedInUserId;


    }

  }
}


