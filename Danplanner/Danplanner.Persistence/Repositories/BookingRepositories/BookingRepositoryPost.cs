using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Interfaces.OrderlineInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.BookingRepositories
{
    public class BookingRepositoryPost : IBookingAdd
    {
        private readonly DbManager _dbManager;

        public BookingRepositoryPost(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task AddBookingAsync(BookingDto bookingDto)
        {
            var booking = new Booking
            {
                BookingResidents = bookingDto.BookingResidents,
                BookingPrice = bookingDto.BookingPrice,
                CheckInDate = bookingDto.CheckInDate,
                CheckOutDate = bookingDto.CheckOutDate,
                UserId = bookingDto.UserId,
                AccommodationId = bookingDto.AccommodationId
            };

            await _dbManager.Booking.AddAsync(booking);
            await _dbManager.SaveChangesAsync();
        }
    }
}
