using Domain.Model;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace WebUI.Services
{
    public interface ISessionManagementService
    {
        Task<bool> ValidateSessionAsync(ClaimsPrincipal user, string currentSessionId);
        Task RegisterSessionAsync(string userId, string sessionId);
        Task InvalidateSessionAsync(string userId);
        string GetCurrentSessionId(HttpContext context);
        void SetSessionCookie(HttpContext context, string sessionId);
        string GenerateNewSessionId();
        string GetSessionCookieName();
    }

    public class SessionManagementService : ISessionManagementService
    {
        private readonly UserManager<ApplicationUser> _userManager;       
        private readonly ILogger<SessionManagementService> _logger;
        private const string SESSION_COOKIE_NAME = "PCS_SessionId"; // Standardized cookie name

        public SessionManagementService(
            UserManager<ApplicationUser> userManager,
             ILogger<SessionManagementService> logger)
        {
            _userManager = userManager;           
            _logger = logger;
        }


        public string GetSessionCookieName()
        {
            return SESSION_COOKIE_NAME;
        }

        public string GetCurrentSessionId(HttpContext context)
        {
            // Simply try to get the session ID from the cookie
            if (context.Request.Cookies.TryGetValue(SESSION_COOKIE_NAME, out string sessionId))
            {
                return sessionId;
            }

            // If no cookie exists, return null
            return null;
        }

        public void SetSessionCookie(HttpContext context, string sessionId)
        {

            string allCookies = string.Join(", ", context.Request.Cookies.Select(c => $"{c.Key}={c.Value}"));
            _logger.LogDebug($"DEBUG: Existing cookies: {allCookies}");

            // Set the cookie with more permissive settings
            context.Response.Cookies.Append(SESSION_COOKIE_NAME, sessionId, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None, // Changed from Lax to None to support cross-site authentication
                Expires = DateTimeOffset.UtcNow.AddDays(1),
                Path = "/", // Ensure cookie is available throughout the application
                IsEssential = true // Mark as essential for GDPR compliance
            });

            _logger.LogDebug($"DEBUG: Setting session cookie: {SESSION_COOKIE_NAME}={sessionId}");
        }

        public string GenerateNewSessionId()
        {
            return Guid.NewGuid().ToString();
        }

        public async Task<bool> ValidateSessionAsync(ClaimsPrincipal user, string currentSessionId)
        {
            try
            {
                var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                {
                    return false;
                }

                var applicationUser = await _userManager.FindByIdAsync(userId);
                if (applicationUser == null)
                {
                    return false;
                }

                // If the user doesn't have a session ID stored in the database, 
                // this is the first login or they logged out properly
                if (string.IsNullOrEmpty(applicationUser.SessionId))
                {
                    return true;
                }

                // Check if the current session ID matches the one stored in the database
                // If it doesn't match, it means the user has logged in from another browser/device
                return applicationUser.SessionId == currentSessionId;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error validating session: {ex}");
                return false;
            }
        }

        public async Task RegisterSessionAsync(string userId, string sessionId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.SessionId = sessionId;
                    user.LastSessionStartTime = DateTime.UtcNow;
                    await _userManager.UpdateAsync(user);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error registering session: {ex}");
            }
        }

        public async Task InvalidateSessionAsync(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.SessionId = null;
                    user.LastSessionStartTime = null;
                    await _userManager.UpdateAsync(user);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error invalidating session: {ex}");
            }
        }
    }
}