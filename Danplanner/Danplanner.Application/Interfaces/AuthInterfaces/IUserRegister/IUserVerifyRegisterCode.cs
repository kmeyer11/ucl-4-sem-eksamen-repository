using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AuthInterfaces.IUserRegister
{
    public interface IUserVerifyRegisterCode
    {
        bool VerifyUserRegisterCode(string email, string code);
    }
}
