using Danplanner.Application.Models.ModelsDto;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Danplanner.Application.Interfaces.UserInterfaces;

namespace Danplanner.Persistence.Repositories.UserRepositories
{
    public class UserRepositoryGet : IUserGetAll, IUserGetByEmail, IUserGetById
    {
        private readonly DbManager _dbManager;

        public UserRepositoryGet(DbManager dbManager)
        {
            _dbManager = dbManager;
        }
        public async Task<List<UserDto>> GetAllUsersAsync()
        {
            return await _dbManager.User
                .Select(u => new UserDto
                {
                    UserId = u.UserId,
                    UserName = u.UserName,
                    UserEmail = u.UserEmail,
                    UserMobile = u.UserMobile,
                    UserAdress = u.UserAdress
                })
                .ToListAsync();
        }

        public async Task<UserDto?> GetUserByEmailAsync(string userEmail)
        {
            var user = await _dbManager.User.FirstOrDefaultAsync(u => u.UserEmail == userEmail);
            if (user == null) return null;

            return new UserDto
            {
                UserId = user.UserId,
                UserName = user.UserName,
                UserEmail = user.UserEmail,
                UserMobile = user.UserMobile,
                UserAdress = user.UserAdress
            };
        }

        public async Task<UserDto?> GetUserByIdAsync(int userId)
        {
            var user = await _dbManager.User.FirstOrDefaultAsync(u => u.UserId == userId);
            if (user == null) return null;

            return new UserDto
            {
                UserId = user.UserId,
                UserName = user.UserName,
                UserEmail = user.UserEmail,
                UserMobile = user.UserMobile,
                UserAdress = user.UserAdress
            };
        }
    }
}
