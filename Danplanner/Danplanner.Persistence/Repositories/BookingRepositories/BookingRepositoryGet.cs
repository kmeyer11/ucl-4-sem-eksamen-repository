using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Persistence.DbMangagerDir;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.BookingRepositories
{
    public class BookingRepositoryGet : IBookingGetById
    {
        private readonly DbManager _dbManager;

        public BookingRepositoryGet(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<BookingDto> BookingGetByIdAsync(int id)
        {
            Booking booking = await _dbManager.Booking.FirstOrDefaultAsync(a => a.BookingId == id); 

            return new BookingDto()
            {
                BookingResidents = booking.BookingResidents,
                BookingPrice = booking.BookingPrice,
                CheckInDate = booking.CheckInDate,
                CheckOutDate = booking.CheckOutDate,
                UserId = booking.UserId,
                AccommodationId = booking.AccommodationId
            };
        }
    }
}
