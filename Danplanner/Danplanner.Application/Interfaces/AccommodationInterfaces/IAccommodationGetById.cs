using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AccommodationInterfaces
{
    public interface IAccommodationGetById
    {
        Task<IReadOnlyCollection<int>> GetAvailableIdsAsync
        (
            DateTime? start,
            DateTime? end
        );
    }
}
