using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.OrderlineInterfaces
{
    public interface IOrderlineAdd
    {
        Task<int> OrderlineAddAsync(int bookingId);
    }
}
