using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AuthInterfaces.IUserLogin
{
    public interface IUserVerifyLoginCode
    {
        Task<string?> VerifyUserLoginCodeAsync(string email, string code);
    }
}
