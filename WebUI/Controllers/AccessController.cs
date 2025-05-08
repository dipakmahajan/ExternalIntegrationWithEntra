using BusinessLayer;
using Data.DataAccess;
using Domain.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using WebUI.Services;

namespace WebUI.Controllers
{
    public class AccessController : Controller
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly AzureAdOptions _azureAdOptions;
        private readonly AzureAdB2COptions _azureAdB2COptions;

        private readonly IUnitOfWork _unitOfWork;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;
        private readonly ISessionManagementService _sessionManagementService;
        private readonly ILogger<AccessController> _logger;

        public AccessController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<AzureAdOptions> azureAdOptions,
            IOptions<AzureAdB2COptions> azureAdB2COptions,
            IUnitOfWork unitOfWork,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration, IWebHostEnvironment env, ISessionManagementService sessionManagementService, ILogger<AccessController> logger)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.roleManager = roleManager;
            _azureAdOptions = azureAdOptions.Value;
            _azureAdB2COptions = azureAdB2COptions.Value;
            _unitOfWork = unitOfWork;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _env = env;
            _sessionManagementService = sessionManagementService;
            _logger = logger;

        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = "/", string? message = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (message is not null)
            {
                ViewData["message"] = message;
            }

            return View();
        }


        [HttpGet("Admin/Login")]
        [AllowAnonymous]
        public IActionResult AdminLogin(string? message = null)
        {
            if (message is not null)
            {
                ViewData["message"] = message;
            }

            return View("Admin/Login");
        }


        [HttpGet("SuperAdmin/Login")]
        [AllowAnonymous]
        public IActionResult SuperAdminLogin(string? message = null)
        {
            if (message is not null)
            {
                ViewData["message"] = message;
            }

            return View("SuperAdmin/Login");
        }

        [AllowAnonymous]
        [HttpGet]
        public ChallengeResult ExternalLogin(string provider, string? returnURL = null, string? role = null)
        {
            _logger.LogInformation("Initiating external login with provider: {Provider}, returnURL: {ReturnURL}, role: {Role}", provider, returnURL, role);
            var redirectURL = Url.Action("RegisterExternalUser", values: new { returnURL });
            var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectURL);
            properties.Items["role"] = role; // Set the role property
            return new ChallengeResult(provider, properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> RegisterExternalUser(string? returnURL = null, string? remoteError = null)
        {
            _logger.LogInformation("Handling external user registration. ReturnURL: {ReturnURL}, RemoteError: {RemoteError}", returnURL, remoteError);
            returnURL ??= Url.Content("~/");
            var message = "";

            if (remoteError != null)
            {
                _logger.LogError("Error from external provider: {RemoteError}", remoteError);
                message = $"Error from external provider: {remoteError}";
                return RedirectToAction("Login", new { message });
            }

            var info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                _logger.LogError("Error loading external login information.");
                message = "Error loading external login information.";
                return RedirectToAction("Login", new { message });
            }

            _logger.LogInformation("External login info retrieved. Provider: {Provider}, ProviderKey: {ProviderKey}", info.LoginProvider, info.ProviderKey);

            // Store external login claims in Session for display in views
            var claimsList = new List<Dictionary<string, string>>();
            foreach (var claim in info.Principal.Claims)
            {
                claimsList.Add(new Dictionary<string, string>
                {
                    { "Type", claim.Type },
                    { "Value", claim.Value }
                });
            }

            // Store in both Session (for persistence) and TempData (for compatibility)
            HttpContext.Session.SetString("ExternalLoginClaims", System.Text.Json.JsonSerializer.Serialize(claimsList));
            TempData["ExternalLoginClaims"] = System.Text.Json.JsonSerializer.Serialize(claimsList);

            // For debugging - also store a simple flag to check if data was stored
            TempData["HasExternalClaims"] = "Yes";
            HttpContext.Session.SetString("HasExternalClaims", "Yes");

            string loginProvider;

            var claimValue = info.Principal.FindFirstValue(CustomClaimTypes.IdentityProvider);
            if (claimValue != null)
            {
                loginProvider = claimValue;
            }
            else
            {
                var tfp = info.Principal.FindFirstValue(CustomClaimTypes.Tfp);
                loginProvider = tfp != null ? Common.LocalAccount : Common.AzureOffice365Account;
            }

            var externalLoginResult = await signInManager.ExternalLoginSignInAsync(loginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            info.LoginProvider = loginProvider;
            if (externalLoginResult.Succeeded)
            {
                _logger.LogInformation("External login succeeded for provider: {Provider}", info.LoginProvider);
                return await HandleExistingUserLogin(info, returnURL);
            }

            _logger.LogWarning("External login failed. Redirecting to user registration.");
            var role = info.AuthenticationProperties?.Items["role"];
            _logger.LogInformation("Role retrieved from authentication properties: {Role}", role);

            if (string.IsNullOrWhiteSpace(role))
            {
                _logger.LogError("Role is null or empty. Cannot assign role to user.");
                message = "Error loading external login information. User role is null.";
                //return RedirectToAction("Login", new { message });
                return SignOutWithErrorMessage(message);
            }

            if (!await roleManager.RoleExistsAsync(role))
            {
                _logger.LogError("Role does not exist in the system: {Role}", role);
                message = "Invalid role specified.";
                return SignOutWithErrorMessage(message);
            }

            var email = info.Principal.FindFirstValue("preferred_username");
            if (email == null)
            {
                email = info.Principal.FindFirstValue("emails");
            }
            var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
            var lastName = info.Principal.FindFirstValue(ClaimTypes.Surname);
            var tenantId = info.Principal.FindFirstValue(CustomClaimTypes.TenantId);

            if (string.IsNullOrWhiteSpace(email))
            {
                var errorMessage = "Error reading user information from the provider.";
                return SignOutWithErrorMessage(errorMessage);
                //return RedirectToAction("Login", new { message });
            }

            var user = new ApplicationUser
            {
                Email = email,
                UserName = email,
                FirstName = firstName,
                LastName = lastName,
                IdProvider = loginProvider,
                EmailConfirmed = true,
                TenantId = tenantId ?? null,
                IsActive = true
            };
            bool superAdminExists = _unitOfWork.ApplicationUsers.CheckIfSuperAdminExists();
            if (!superAdminExists && role == "SuperAdmin")
            {
                user.IsActive = true;
            }

            var createUserResult = await userManager.CreateAsync(user);
            if (!createUserResult.Succeeded)
            {
                foreach (var item in createUserResult.Errors)
                {
                    message = string.Join("\n", message, item.Description);
                }
                return SignOutWithErrorMessage(message);
            }

            await userManager.AddToRoleAsync(user, role);
            _logger.LogInformation("Role {Role} assigned to user {UserId}", role, user.Id);

            var addLoginResult = await userManager.AddLoginAsync(user, info);

            if (!addLoginResult.Succeeded)
            {
                message = "There was an error while logging you in.";
                return SignOutWithErrorMessage(message);
            }
            
            message = "Registration successful! You can now log in to access your account.";
            return RedirectToAction("Information", "Home", new { Message = message });

            //await signInManager.SignInAsync(user, isPersistent: false, loginProvider);
            //return LocalRedirect(returnURL);
        }

        private async Task<IActionResult> HandleExistingUserLogin(ExternalLoginInfo info, string returnURL)
        {
            _logger.LogInformation("Handling existing user login. Provider: {Provider}, ReturnURL: {ReturnURL}", info.LoginProvider, returnURL);
            var loggedInUserEmail = info.Principal.FindFirstValue("preferred_username");
            if (loggedInUserEmail == null)
            {
                _logger.LogError("Failed to retrieve preferred_username from external login info. Using emails field instead.");
                loggedInUserEmail = info.Principal.FindFirstValue("emails");
            }
            var loggedInUser = await userManager.FindByNameAsync(loggedInUserEmail);

            var errorMessageForInactiveAndDistrictNull = "Your account is not activated OR a district has not been assigned to you.\nYou currently do not have access to the application. Please contact PCS support team for assistance.";

            if (loggedInUser == null || !loggedInUser.IsActive)
            {
                _logger.LogWarning("User not found or inactive. Email: {Email}", loggedInUserEmail);
                var errorMessage = errorMessageForInactiveAndDistrictNull;
                return SignOutWithErrorMessage(errorMessage);
            }

            if (loggedInUser.IdProvider == Common.LocalAccount && !loggedInUser.EmailConfirmed)
            {
                var errorMessageForEmailVerification = $"Your account is not yet verified.To access the application, please check your inbox for a verification mail.Make sure to check your spam or junk folder";
                var errorMessage = errorMessageForEmailVerification;
                return SignOutWithErrorMessage(errorMessage);
            }
            var loggedInUserRole = (await userManager.GetRolesAsync(loggedInUser)).FirstOrDefault();
            if (loggedInUserRole == null)
            {
                var errorMessage = "Invalid user role.";
                return SignOutWithErrorMessage(errorMessage);
            }

            loggedInUser.LastLoginDateTime = DateTime.Now;
            await userManager.UpdateAsync(loggedInUser);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, info.Principal);
            // Store user information in session
            HttpContext.Session.SetString("UserEmail", loggedInUser.Email);
            HttpContext.Session.SetString("UserRole", loggedInUserRole);
            HttpContext.Session.SetString("UserId", loggedInUser.Id);

            // Generate a new session ID and set it in the cookie
            string sessionId = _sessionManagementService.GenerateNewSessionId();
            _sessionManagementService.SetSessionCookie(HttpContext, sessionId);

            _logger.LogDebug($"Login: Generated new session ID {sessionId} for user {loggedInUser.Id}");

            // Register the session in the database
            await _sessionManagementService.RegisterSessionAsync(loggedInUser.Id, sessionId);

            return loggedInUserRole switch
            {

                "SuperAdmin" => !string.IsNullOrWhiteSpace(returnURL) ? LocalRedirect(returnURL) : RedirectToAction("Index", "SuperAdmin"),
                "Admin" => !string.IsNullOrWhiteSpace(returnURL) ? LocalRedirect(returnURL) : RedirectToAction("Index", "Admin"),
                "User" => !string.IsNullOrWhiteSpace(returnURL) ? LocalRedirect(returnURL) : RedirectToAction("Index", "User"),
                _ => RedirectToAction("Login", new { message = "Invalid user role." })
            };

        }

        private IActionResult SignOutWithErrorMessage(string errorMessage)
        {
            SignOutAndRedirect();
            ViewData["ErrorMessage"] = errorMessage;
            return AzureAdB2cLogout("Error", "Home", errorMessage);
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            try
            {
                await SignOutAndRedirect();
                // Redirect to Entra External ID logout
                return AzureAdB2cLogout("Index", "Home");
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                //_errorLogService.LogError(new ErrorLog
                //{
                //    Message = $"Logout - Error during logout: {ex}",
                //    UserId = HttpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
                //});
                return RedirectToAction("Error", "Home", new { message = "An error occurred during logout." });
            }
        }

        private async Task SignOutAndRedirect()
        {
            try
            {
                await signInManager.SignOutAsync();
                // Sign out of both Azure AD and Azure AD B2C OpenID Connect schemes
                await HttpContext.SignOutAsync("AzureAd");
                await HttpContext.SignOutAsync("AzureAdB2C");

                // Sign out of cookies
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                var loggedInUser = await userManager.GetUserAsync(HttpContext.User);
                if (loggedInUser != null)
                {
                    // Invalidate the session
                    await _sessionManagementService.InvalidateSessionAsync(loggedInUser.Id);

                }

                // Clear session
                HttpContext.Session.Clear();

                // Clear the session cookie
                Response.Cookies.Delete(_sessionManagementService.GetSessionCookieName());
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);

            }
        }

        private string GetLogoutURL(string redirectURLAfterLogout)
        {
            // Determine which authentication scheme was used for the current user
            var authenticationMethod = User.FindFirstValue(ClaimTypes.AuthenticationMethod);
            var encodedRedirectUrl = Uri.EscapeDataString(redirectURLAfterLogout);

            if (authenticationMethod != null && !authenticationMethod.Contains(Common.AzureOffice365Account))
            {
                var instance = _azureAdB2COptions.Instance.TrimEnd('/');
                // Azure AD B2C (Entra External ID) logout URL
                return $"{instance}/{_azureAdB2COptions.Domain}/{_azureAdB2COptions.SignUpSignInPolicyId}/oauth2/v2.0/logout?post_logout_redirect_uri={encodedRedirectUrl}";
            }
            else
            {
                // Azure AD (B2B) logout URL
                // Remove any trailing slash from the Instance URL
                var instance = _azureAdOptions.Instance.TrimEnd('/');

                // Construct the logout URL for Azure AD
                return $"{instance}/{_azureAdOptions.TenantId}/oauth2/v2.0/logout?post_logout_redirect_uri={encodedRedirectUrl}";
            }
        }

        private IActionResult AzureAdB2cLogout(string action, string controller, string? message = null)
        {
            string errorMessage = message != null ? Uri.EscapeDataString(message) : string.Empty;
            string? callbackUrlAfterLogout = Url.Action(action, controller, new { errorMessage }, protocol: Request.Scheme) ?? string.Empty;

            // Store the final redirect URL in TempData so it can be retrieved in the callback
            TempData["PostLogoutRedirectUri"] = callbackUrlAfterLogout;

            string azureDbB2cLogoutUrl = GetLogoutURL(callbackUrlAfterLogout);
            //Logout from azure Ad B2C and navigate to application home page    
            return Redirect(azureDbB2cLogoutUrl);
        }


        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToPage("/Index");
            }
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Error", "Home", new { errorMessage = $"Unable to load user with ID '{userId}'." });
            }

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await userManager.ConfirmEmailAsync(user, code);
            var message = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
            return RedirectToAction("Information", "Home", new { Message = message });
        }

        public IActionResult ResetPassword()
        {
            string policy = _azureAdB2COptions.ResetPasswordPolicyId;//_configuration["AzureAdB2C:PasswordResetPolicyId"];

            var properties = new AuthenticationProperties
            {
                RedirectUri = "/",
                Items = {
                    { "policy", policy }
                }
            };
            return new ChallengeResult("AzureAdB2C", properties);
        }

    }
}
public static class CustomClaimTypes
{
    public const string IdentityProvider = "http://schemas.microsoft.com/identity/claims/identityprovider";
    //public const string AuthenticationMethod = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod";
    public const string TenantId = "http://schemas.microsoft.com/identity/claims/tenantid";
    public const string Tfp = "tfp";
}
