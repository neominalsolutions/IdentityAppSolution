using IdentityAPI;
using IdentityAPI.Identity.Contexts;
using IdentityAPI.Identity.Models;
using IdentityAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(opt =>
{

  var securityScheme = new OpenApiSecurityScheme()
  {
    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
    Name = "Authorization",
    In = ParameterLocation.Header,
    Type = SecuritySchemeType.Http,
    Scheme = "Bearer",
    BearerFormat = "JWT" // Optional
  };

  var securityRequirement = new OpenApiSecurityRequirement
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "bearerAuth"
            }
        },
        new string[] {}
    }
};

  opt.AddSecurityDefinition("bearerAuth", securityScheme);
  opt.AddSecurityRequirement(securityRequirement);
});



builder.Services.AddDbContext<AppIdentityDbContext>(opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("IdentityDbConn")));

builder.Services.AddIdentity<AppUser, AppRole>(cfg =>
{
  cfg.User.RequireUniqueEmail = true;
  cfg.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
  cfg.Password.RequireDigit = true;
  cfg.SignIn.RequireConfirmedEmail = true;
  cfg.ClaimsIdentity.UserNameClaimType = "UserId";

}).AddEntityFrameworkStores<AppIdentityDbContext>().AddDefaultTokenProviders();

// https://learn.microsoft.com/en-us/aspnet/core/security/authentication/2fa?view=aspnetcore-1.1

builder.Services.AddScoped<IAccessTokenService, JwtTokenService>();

var key = Encoding.ASCII.GetBytes(JWTSettings.SecretKey);




builder.Services.AddAuthentication(x =>
{
  x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opt =>
{
  opt.RequireHttpsMetadata = true;
  opt.SaveToken = true;
  opt.TokenValidationParameters = new TokenValidationParameters
  {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false,
    ValidateAudience = false,
    ValidateLifetime = true,
    LifetimeValidator = (notbefore,expires,securityToken,validationParamaters) =>
    {
      Console.Out.WriteLineAsync("LifetimeValidator Event");
      return expires != null && expires.Value > DateTime.UtcNow;
    }
  };

  opt.Events = new JwtBearerEvents()
  {
    OnAuthenticationFailed = c =>
    {
      // Serilog
      Console.Out.WriteLineAsync("Authentication Failed" + c.Exception.Message);
      return Task.CompletedTask;
    },
    OnTokenValidated = c =>
    {
      Console.Out.WriteLineAsync("Authentication Valiated" + c.Result);
      return Task.CompletedTask;
    },
    OnForbidden = c =>
    {
      Console.Out.WriteAsync("Yetki Yok" + c.Principal?.Identity?.Name);
      return Task.CompletedTask;
    }
  };
});

// claim odaklý çalýþýr.
// her uygulama run olduðunda bir kez çalýþsýn. Dinamik Policy üreten bir method

//  ClaimTypes.Role => Role kullanýrken buna dikkat.

builder.Services.AddAuthorization(opt =>
{
  opt.AddPolicy("UserPermissionByAdmin", policy =>
  {
    policy.RequireAuthenticatedUser();
    policy.RequireRole("admin");
    policy.RequireClaim("User", "Insert","Update","Delete","Approve");
  });

  opt.AddPolicy("UserPermissionByManager", policy =>
  {
    policy.RequireAuthenticatedUser();
    policy.RequireRole("manager");
    policy.RequireClaim("User", "Insert", "Update");
  });
});


var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
