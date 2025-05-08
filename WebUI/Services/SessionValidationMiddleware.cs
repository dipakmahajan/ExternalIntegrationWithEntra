using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace WebUI.Services
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionValidationMiddleware> _logger;

        public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context, ISessionManagementService sessionManagementService)
        {
            _logger.LogInformation("SessionValidationMiddleware invoked for path: {Path}", context?.Request?.Path);

            // Log user claims for debugging
            var userClaims = string.Join(", ", context.User.Claims.Select(c => $"{c.Type}={c.Value}"));
            _logger.LogDebug("DEBUG: User claims: {Claims}", userClaims);

            // Log session details for debugging unauthenticated requests
            var currentSessionId = sessionManagementService.GetCurrentSessionId(context);
            _logger.LogDebug("DEBUG: Current session ID: {SessionId}", currentSessionId);

            // Refined skip conditions
            if (context.User?.Identity?.IsAuthenticated != true)
            {
                _logger.LogInformation("Skipping validation: User is not authenticated. Path: {Path}", context.Request?.Path);
                await _next(context);
                return;
            }

            var skipPaths = new[]
            {
                "/Access",
                "/Admin/Login",
                "/SuperAdmin/Login",
                "/Home/Error",
                "/Home/Information",
                "/static",
                "/.well-known"
            };

            foreach (var skipPath in skipPaths)
            {
                if (context.Request.Path.StartsWithSegments(skipPath, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("Skipping validation: Path starts with {SkipPath}. Path: {Path}", skipPath, context.Request.Path);
                    await _next(context);
                    return;
                }
            }

            // Debugging: Log session validation details
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            _logger.LogInformation("Validating session. UserId: {UserId}, SessionId: {SessionId}, Path: {Path}", userId, currentSessionId, context.Request.Path);

            if (!string.IsNullOrEmpty(currentSessionId) && !string.IsNullOrEmpty(userId))
            {
                var isValidSession = await sessionManagementService.ValidateSessionAsync(context.User, currentSessionId);

                if (!isValidSession)
                {
                    _logger.LogWarning("Invalid session detected. UserId: {UserId}, SessionId: {SessionId}, Path: {Path}", userId, currentSessionId, context.Request.Path);
                    _logger.LogDebug("DEBUG: Invalid session details. UserId: {UserId}, SessionId: {SessionId}", userId, currentSessionId);
                    await ForceLogout(context, "Your account has been logged in from another browser or device. Please log in again.");
                    return;
                }
            }
            else
            {
                _logger.LogWarning("Missing session or user ID. UserId: {UserId}, SessionId: {SessionId}, Path: {Path}", userId ?? "null", currentSessionId ?? "null", context.Request.Path);
            }

            _logger.LogInformation("Session validation passed for UserId: {UserId}, Path: {Path}", userId, context.Request.Path);
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