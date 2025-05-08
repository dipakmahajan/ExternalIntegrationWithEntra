using Data;
using Data.DataAccess;
using Domain.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using WebUI.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc;
using NToastNotify;
using Serilog;
using Microsoft.Identity.Web.UI;
using Microsoft.Identity.Web;


var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration().CreateLogger();
builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration.ReadFrom.Configuration(context.Configuration);
});
// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
});
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
//builder.Services.AddDistributedSqlServerCache(options =>
//{
//    options.ConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
//    options.SchemaName = "dbo";
//    options.TableName = "TokenCache";
//});
builder.Services.AddCors(
        options => options.AddPolicy("AllowCors",
        builder =>
        {
            builder.AllowAnyHeader();
        })
    );


builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
        //options.SerializerSettings.ContractResolver = null;
    });


builder.Services.AddRazorPages();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHostedService<SeedHostedService>();
builder.Services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
builder.Services.AddSingleton<IUrlHelper>(provider =>
{
    var actionContext = provider.GetRequiredService<IActionContextAccessor>().ActionContext;
    return new UrlHelper(actionContext);
});

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set session idle timeout to 30 minutes
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddMvc()
    .AddNToastNotifyToastr(new ToastrOptions()
    {
        ProgressBar = true,
        PositionClass = ToastPositions.TopFullWidth,

    })
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = null;
    });


builder.Services.AddAuthorization(options =>
{
    //options.FallbackPolicy = options.DefaultPolicy;
    options.AddPolicy("SuperAdminPolicy", policy => policy.RequireRole("SuperAdmin"));
    options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserPolicy", policy => policy.RequireRole("User"));
});

builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<ISessionManagementService, SessionManagementService>();

// Add services to the container.
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
    // Handling SameSite cookie according to https://learn.microsoft.com/aspnet/core/security/samesite?view=aspnetcore-3.1
    options.HandleSameSiteCookieCompatibility();
});

// Configure authentication with a single AddAuthentication call
var authBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme; // Use cookies for challenge instead of AzureAd

});
authBuilder.AddCookie(options =>
{
    var timeoutMinutes = int.Parse(builder.Configuration["SessionSettings:IdleTimeoutMinutes"]);

    options.LoginPath = "/Access/Login";
    options.LogoutPath = "/Access/Logout";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(timeoutMinutes);
    options.SlidingExpiration = true;
    options.ReturnUrlParameter = "returnUrl"; // Ensures return URL is passed

    // Add these settings:
    options.Cookie.SameSite = SameSiteMode.None; // Important for cross-site authentication
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Events = new CookieAuthenticationEvents
    {
        OnRedirectToLogin = context =>
        {
            if (!context.Request.Path.StartsWithSegments("/Access/ExternalLogin"))
            {
                var returnUrl = context.Request.Path + context.Request.QueryString;
                var loginUrl = $"/Access/Login?returnUrl={Uri.EscapeDataString(returnUrl)}";
                context.Response.Redirect(loginUrl);
                return Task.CompletedTask;
            }

            return Task.CompletedTask;
        }
    };
});

// Add Azure AD (B2B) authentication
authBuilder.AddMicrosoftIdentityWebApp(builder.Configuration, "AzureAd", openIdConnectScheme: "AzureAd", cookieScheme: null);

// Add Azure AD B2C authentication
authBuilder.AddMicrosoftIdentityWebApp(builder.Configuration, "AzureAdB2C", openIdConnectScheme: "AzureAdB2C", cookieScheme: null);


builder.Services.AddControllersWithViews()
    .AddMicrosoftIdentityUI();
builder.Services.AddRazorPages();


builder.Services.AddOptions();
builder.Services.Configure<AzureAdOptions>(builder.Configuration.GetSection("AzureAd"));
builder.Services.Configure<AzureAdB2COptions>(builder.Configuration.GetSection("AzureAdB2C"));


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCookiePolicy();
app.UseRouting();
app.UseNToastNotify();
app.UseAuthentication();
app.UseSession();
app.UseSessionValidation();
app.UseAuthorization();
app.UseMiddleware<IdleTimeoutMiddleware>();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
