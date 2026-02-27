using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Danplanner.Persistence.Repositories.AdminRepositories
{
    public class AdminRepositoryGet : IAdminGetById, IAdminGetAll
    {
        private readonly DbManager _dbManager;

        public AdminRepositoryGet(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<Admin?> GetAdminByIdAsync(int adminId)
        {
            return await _dbManager.Admin.FirstOrDefaultAsync(a => a.AdminId == adminId);
        }
        public async Task<List<Admin>> LoadAdminListAsync()
        {
            return await _dbManager.Admin.ToListAsync();
        }
    }
}
