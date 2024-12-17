using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityAPI.Filters
{
  public class PermissionFilterAttribute : ActionFilterAttribute
  {
    private readonly string PermissionType;

    private readonly string PermissionValue;
    public PermissionFilterAttribute(string permissionType, string permissionvalue)
    {
      PermissionType = permissionType;
      PermissionValue = permissionvalue;
    }

    // Burada login olan user bulunup onun bu action'a yetkili olup olmadığı kontrol edilebilir
    // Action Tetiklenemeden önce
    public override void OnActionExecuting(ActionExecutingContext context)
    {
      Console.Out.WriteLine("Action öncesi kontrol");

      //context.Result = new UnauthorizedObjectResult({ });

      base.OnActionExecuting(context);
    }
  }
}
