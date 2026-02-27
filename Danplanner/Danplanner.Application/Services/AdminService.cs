using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Services
{
    public class AdminService
    {
        private readonly IAdminGetAll _adminGetAll;

        public AdminService(IAdminGetAll adminGetAll)
        {
            _adminGetAll = adminGetAll;
        }

        public async Task<List<Admin>> GetAllAdminsAsync()
        {
            var admins = await _adminGetAll.LoadAdminListAsync();
            return admins.Select(a => new Admin { AdminId = a.AdminId }).ToList();
        }
    }
}
