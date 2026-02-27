using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Interfaces.AddonInterfaces
{
    public interface IAddonGetByBookingId
    {
        Task<List<Addon>> AddonGetByBookingIdAsync(int bookingId);
    }
}
