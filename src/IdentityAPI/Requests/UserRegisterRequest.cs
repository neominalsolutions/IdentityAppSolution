using System.ComponentModel;

namespace IdentityAPI.Requests
{
  public record UserRegisterRequest([property: DefaultValue("test.user")] string Name, [property: DefaultValue("test@test.com")]  string Email, [property: DefaultValue("P@@sword1")]  string Password, [property: DefaultValue("admin")]  string RoleName);
  
}
