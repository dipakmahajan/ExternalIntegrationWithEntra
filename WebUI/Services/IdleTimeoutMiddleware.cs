using Domain.Model;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace WebUI.Services
{
    public class IdleTimeoutMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public static readonly Dictionary<string, DateTime> UserActivity = new();

        public IdleTimeoutMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;           
        }

        public async Task Invoke(HttpContext context)
        {            
            var userId = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(userId))
            {
                lock (UserActivity)
                {
                    if (UserActivity.TryGetValue(userId, out var lastActivity))
                    {
                        var idleTimeoutMinutes = int.Parse(_configuration["SessionSettings:IdleTimeoutMinutes"]);

                        if ((DateTime.UtcNow - lastActivity).TotalMinutes > idleTimeoutMinutes)
                        {
                            // Remove user from UserActivity dictionary
                            UserActivity.Remove(userId);
                            // Redirect user to logout if idle timeout exceeded
                            context.Response.Redirect("/Access/Logout");
                            return;
                        }
                    }

                    // Update the last activity timestamp
                    UserActivity[userId] = DateTime.UtcNow;
                }
            }

            await _next(context);
        }
    }


}
