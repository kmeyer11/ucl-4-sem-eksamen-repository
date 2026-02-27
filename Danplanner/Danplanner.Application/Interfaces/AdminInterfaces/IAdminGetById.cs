using Danplanner.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AdminInterfaces
{
    public interface IAdminGetById
    {
        Task<Admin?> GetAdminByIdAsync(int adminId);

    }
}
