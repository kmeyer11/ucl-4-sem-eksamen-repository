using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AuthInterfaces.IUserLogin
{
    public interface IUserRequestLoginCode
    {
        Task<bool> RequestUserLoginCodeAsync(string email);
    }
}
