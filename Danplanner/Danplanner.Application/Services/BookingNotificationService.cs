using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Models;
using Danplanner.Application.Models.ModelsDto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Services
{
    public class BookingNotificationService : IBookingNotificationService
    {
        private readonly HttpClient _httpClient;

        public BookingNotificationService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task SendNotificationsAsync(BookingNotification notification)
        {
            var orderConfirmation = new OrderConfirmationDto
            {
                Date = DateTime.Now,
                UserEmail = notification.UserEmail,
                UserName = notification.UserName,
                CheckInDate = notification.CheckInDate,
                CheckOutDate = notification.CheckOutDate
            };

            await _httpClient.PostAsJsonAsync(
                "http://localhost:8080/orderNotify", orderConfirmation);

            var paymentConfirmation = new PaymentConfirmationDto
            {
                UserEmail = notification.UserEmail,
                UserName = notification.UserName,
                Date = DateTime.Now,
                PaymentId = 0,
                OrderlineId = 0,
                AccommodationName = notification.AccommodationName,
                BookingResidents = notification.BookingResidents,
                BookingCheckIn = notification.CheckInDate,
                BookingCheckOut = notification.CheckOutDate,
                Price = (decimal)notification.Price
            };

            await _httpClient.PostAsJsonAsync(
                "http://localhost:8080/paymentNotify", paymentConfirmation);
        }
    }
}
