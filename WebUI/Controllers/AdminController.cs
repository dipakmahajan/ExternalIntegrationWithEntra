using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebUI.Models;

namespace WebUI.Controllers
{
    [Authorize(Roles = "Admin,SuperAdmin")]
    public class AdminController : Controller
    {

        public AdminController()
        {

        }
        [Authorize(Roles = "Admin")]
        public IActionResult Index()
        {
            return View(new AdminViewModel());
        }



    }
}
