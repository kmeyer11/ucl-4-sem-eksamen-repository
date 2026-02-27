using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.UserRepositories
{
    public class UserRepositoryDelete : IUserDelete
    {
        private readonly DbManager _dbManager;

        public UserRepositoryDelete(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task DeleteUserAsync(int userId)
        {
            var user = await _dbManager.User.FindAsync(userId);
            if (user != null)
            {
                _dbManager.User.Remove(user);
                await _dbManager.SaveChangesAsync();
            }
        }
    }
}
