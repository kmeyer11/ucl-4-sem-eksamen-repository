using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Persistence.Repositories.UserRepositories
{
    public class UserRepositoryPut : IUserUpdate
    {
        private readonly DbManager _dbManager;

        public UserRepositoryPut(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<UserDto> UpdateUserAsync(UserDto userDto)
        {
            var user = await _dbManager.User.FirstOrDefaultAsync(u => u.UserId == userDto.UserId);
            if (user == null) return null;

            user.UserName = userDto.UserName;
            user.UserEmail = userDto.UserEmail;
            user.UserMobile = userDto.UserMobile;
            user.UserAdress = userDto.UserAdress;

            await _dbManager.SaveChangesAsync();

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
