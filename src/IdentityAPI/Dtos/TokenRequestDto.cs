using System.ComponentModel;

namespace IdentityAPI.Dtos
{
  public record TokenRequestDto([property: DefaultValue("test@test.com")]  string Email, [property: DefaultValue("12345")]  string Password);
}
