using Domain.Model;
using Microsoft.EntityFrameworkCore;
using System.Collections;
using System.Data;

namespace Data.DataAccess
{
    public interface IApplicationUserRepository : IRepository<ApplicationUser>
    {       
        bool CheckIfSuperAdminExists();      
    }

    public class ApplicationUserRepository : Repository<ApplicationUser>, IApplicationUserRepository
    {
        private ApplicationDbContext _context;

        public ApplicationUserRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }
       

        public bool CheckIfSuperAdminExists()
        {
            var roleName = "SuperAdmin";
            var roleId = _context.Roles.Where(r => r.Name == roleName).Select(a => a.Id).FirstOrDefault();
            List<string> userIdsBasedOnRole = _context.UserRoles.Where(a => a.RoleId == roleId).Select(b => b.UserId).Distinct().ToList();
            if (userIdsBasedOnRole != null && userIdsBasedOnRole.Any())
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}