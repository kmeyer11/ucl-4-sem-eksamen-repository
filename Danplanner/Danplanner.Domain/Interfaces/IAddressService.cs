using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Domain.Interfaces
{
    public interface IAddressService
    {
        Task<List<string>> GetAddressesAsync(string query);
    }
}
