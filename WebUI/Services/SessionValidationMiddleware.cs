using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace WebUI.Services
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, ISessionManagementService sessionManagementService)
        {
            // Skip validation for non-authenticated requests or authentication-related paths
            if (!context.User.Identity.IsAuthenticated ||
                context.Request.Path.StartsWithSegments("/Access") ||
                context.Request.Path.StartsWithSegments("/Admin/Login") ||
                context.Request.Path.StartsWithSegments("/SuperAdmin/Login") ||
                context.Request.Path.StartsWithSegments("/Home/Error") ||
                context.Request.Path.StartsWithSegments("/Home/Information") ||
                context.Request.Path.StartsWithSegments("/static") ||
                context.Request.Path.StartsWithSegments("/.well-known"))
            {
                await _next(context);
                return;
            }

            // Get the current session ID from the cookie using the service
            var currentSessionId = sessionManagementService.GetCurrentSessionId(context);
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Only validate if we have both a user ID and a session ID
            // This allows initial logins where the session ID hasn't been set yet
            if (!string.IsNullOrEmpty(currentSessionId) && !string.IsNullOrEmpty(userId))
            {
                var isValidSession = await sessionManagementService.ValidateSessionAsync(context.User, currentSessionId);

                if (!isValidSession)
                {
                    // Session is invalid - user is logged in elsewhere
                    await ForceLogout(context, "Your account has been logged in from another browser or device. Please log in again.");
                    return;
                }
            }

            await _next(context);
        }

        private async Task ForceLogout(HttpContext context, string message)
        {
            // Clear authentication cookies
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync("AzureAd");
            await context.SignOutAsync("AzureAdB2C");

            // Clear session
            context.Session.Clear();

            // Redirect to login page with message
            context.Response.Redirect($"/Home/Error?errorMessage={Uri.EscapeDataString(message)}");
        }
    }

    // Extension method to add the middleware to the pipeline
    public static class SessionValidationMiddlewareExtensions
    {
        public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SessionValidationMiddleware>();
        }
    }
}