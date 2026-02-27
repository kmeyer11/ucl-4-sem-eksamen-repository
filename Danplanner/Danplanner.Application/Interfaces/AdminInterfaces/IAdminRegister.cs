using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.AdminInterfaces
{
    public interface IAdminRegister
    {
        Task<AdminDto> RegisterAdminAsync(AdminDto request);
    }
}
