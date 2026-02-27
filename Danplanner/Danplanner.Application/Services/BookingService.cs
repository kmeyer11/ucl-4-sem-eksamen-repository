using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Interfaces.OrderlineInterfaces;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Services
{
    public class BookingService : IBookingAdd
    {
        private readonly HttpClient _httpClient;
        private readonly IUserGetById _userGetById;
        private readonly IOrderlineAdd _orderlineAdd;
        private readonly IOrderlineGetById _orderlineGetById;
        private readonly IBookingGetById _bookingGetById;
        private readonly IAccommodationGetById2 _accommodationGetById2;
        private readonly IAddonGetByBookingId _addonGetByBookingId;

        public BookingService
        (
            HttpClient httpClient,
            IUserGetById userGetById,
            IOrderlineAdd orderlineAdd,
            IOrderlineGetById orderlineGetById,
            IBookingGetById bookingGetById,
            IAccommodationGetById2 accommodationGetById2,
            IAddonGetByBookingId addonGetByBookingId
        )
        {
            _httpClient = httpClient;
            _userGetById = userGetById;
            _orderlineAdd = orderlineAdd;
            _orderlineGetById = orderlineGetById;
            _bookingGetById = bookingGetById;
            _accommodationGetById2 = accommodationGetById2;
            _addonGetByBookingId = addonGetByBookingId;
        }

        public async Task AddBookingAsync(BookingDto bookingDto)
        {
            // Send booking til DB
            var response = await _httpClient.PostAsJsonAsync("https://localhost:7026/api/booking", bookingDto);
            response.EnsureSuccessStatusCode();

            // Opret orderline og hent id til faktura
            int orderlineId = await _orderlineAdd.OrderlineAddAsync(bookingDto.BookingId);

            // Hent orderline
            OrderlineDto orderline = await _orderlineGetById.OrderlineGetByIdAsync(orderlineId);

            // Hent booking fra fremmed nøgle
            BookingDto booking = await _bookingGetById.BookingGetByIdAsync(orderline.BookingId);

            // Henter info på vores user
            UserDto user = await _userGetById.GetUserByIdAsync(booking.UserId);

            // Hent accommodation
            AccommodationDto accommodation = await _accommodationGetById2.AccommodationGetByIdAsync(booking.AccommodationId);
        }
    }
}
