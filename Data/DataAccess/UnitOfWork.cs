namespace Data.DataAccess
{
    public interface IUnitOfWork : IDisposable
    {
        IApplicationUserRepository ApplicationUsers { get; set; }
    }
    public class UnitOfWork : IUnitOfWork
    {
        private ApplicationDbContext _context;
        public UnitOfWork(ApplicationDbContext context)
        {
            _context = context;

            ApplicationUsers = new ApplicationUserRepository(_context);

        }

        public IApplicationUserRepository ApplicationUsers { get; set; }


        public void Dispose()
        {
            _context.Dispose();
        }
    }


}
