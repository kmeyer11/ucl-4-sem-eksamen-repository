using Azure.Core;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.UserRepositories
{
    public class UserRepositoryPost : IUserAdd
    {
        private readonly DbManager _dbManager;

        public UserRepositoryPost(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task AddUserAsync(UserDto userDto)
        {
            var user = new User
            {
                UserAdress = userDto.UserAdress,
                UserMobile = userDto.UserMobile,
                UserEmail = userDto.UserEmail,
                UserName = userDto.UserName,
            };
            await _dbManager.User.AddAsync(user);
            await _dbManager.SaveChangesAsync();
        }

    }
}
