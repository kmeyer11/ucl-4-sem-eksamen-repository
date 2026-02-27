using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.LoginDto;

namespace Danplanner.Application.Interfaces.AuthInterfaces
{
    public interface ILogin
    {
        Task<string?> LoginAsync(LoginDto request);
    }
}
