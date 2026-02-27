using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.OrderlineInterfaces
{
    public interface IOrderlineGetById
    {
        Task<OrderlineDto> OrderlineGetByIdAsync(int orderlineId);
    }
}
