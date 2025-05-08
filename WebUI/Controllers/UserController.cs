using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebUI.Models;

namespace WebUI.Controllers
{
    [Authorize(Roles = "User")]
    public class UserController : Controller
    {

        public UserController()
        {
        }
        public async Task<IActionResult> Index()
        {
            var userViewModel = new UserViewModel();
            return View(userViewModel);
        }

    }
}
