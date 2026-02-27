using Danplanner.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.BookingInterfaces
{
    public interface IBookingAdd
    {
        Task AddBookingAsync(BookingDto bookingDto);
    }
}
