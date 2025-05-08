using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebUI.Models;

namespace WebUI.Controllers
{
    [Authorize(Roles = "SuperAdmin")]
    public class SuperAdminController : Controller
    {
        public SuperAdminController()
        {
        }
        [Authorize]
        public IActionResult Index()
        {
            return View(new SuperAdminViewModel());
        }

    }

}
