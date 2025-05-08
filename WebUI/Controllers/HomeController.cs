using Microsoft.AspNetCore.Mvc;
using NToastNotify;
using System.Diagnostics;
using System.Web;
using WebUI.Models;

namespace WebUI.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IToastNotification _toastNotification;

        public HomeController(ILogger<HomeController> logger, IToastNotification toastNotification)
        {
            _logger = logger;
            _toastNotification = toastNotification;

        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error(string errorMessage)
        {
            ViewBag.ErrorMessage = HttpUtility.UrlDecode(errorMessage); 
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Information(string Message)
        {
            ViewBag.Message = Message;
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
              

        public IActionResult Profile()
        {
            return View();
        }
    }
}
