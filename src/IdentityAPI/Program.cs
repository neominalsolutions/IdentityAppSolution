using IdentityAPI.Identity.Contexts;
using IdentityAPI.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


builder.Services.AddDbContext<AppIdentityDbContext>(opt => opt.UseSqlServer(builder.Configuration.GetConnectionString("IdentityDbConn")));

builder.Services.AddIdentity<AppUser, AppRole>(cfg =>
{
  cfg.User.RequireUniqueEmail = true;
  cfg.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
  cfg.Password.RequireDigit = true;
  cfg.SignIn.RequireConfirmedEmail = true;

}).AddEntityFrameworkStores<AppIdentityDbContext>().AddDefaultTokenProviders();

// https://learn.microsoft.com/en-us/aspnet/core/security/authentication/2fa?view=aspnetcore-1.1


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
