using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Interfaces.AuthInterfaces.ITokenService
{
    public interface IAdminCreateToken
    {
        string CreateTokenForAdmin(Admin admin);
    }
}
