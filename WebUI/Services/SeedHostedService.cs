using Data.Seed;

namespace WebUI.Services
{
    public class SeedHostedService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IConfiguration _configuration;

        public SeedHostedService(IServiceProvider serviceProvider,IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _configuration = configuration;
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var services = scope.ServiceProvider;
            await SeedDefaultData.SeedRoles(services);      

        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    }
}
