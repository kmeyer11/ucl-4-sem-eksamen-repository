using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.AuthInterfaces.IUserRegister
{
    public interface IUserRegister
    {
        Task<UserDto> RegisterUserAsync(UserDto request);
    }
}
