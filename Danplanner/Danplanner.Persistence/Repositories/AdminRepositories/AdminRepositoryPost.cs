using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.AdminRepositories
{
    public class AdminRepositoryPost : IAdminAdd
    {
        private readonly DbManager _dbManager;

        public AdminRepositoryPost(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task AddAdminAsync(Admin admin)
        {
            await _dbManager.Admin.AddAsync(admin);
            await _dbManager.SaveChangesAsync();
        }
    }
}
