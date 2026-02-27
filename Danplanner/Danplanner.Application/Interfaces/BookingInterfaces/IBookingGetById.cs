using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.BookingInterfaces
{
    public interface IBookingGetById
    {
        Task <BookingDto> BookingGetByIdAsync(int id);
    }
}
