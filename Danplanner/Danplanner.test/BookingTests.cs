using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Client.Controllers;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Threading.Tasks;

namespace Danplanner.test;

[TestClass]
public class BookingTests
{
    [TestMethod]
    public async Task CreateBookingAsync()
    {
        var bookingAddMock = new Mock<IBookingAdd>();

        var controller = new BookingController(bookingAddMock.Object);

        var dto = new BookingDto
        {
            BookingResidents = 2,
            BookingPrice = 900,
            CheckInDate = new DateTime(2025, 6, 1),
            CheckOutDate = new DateTime(2025, 6, 4),
            UserId = 10,
            AccommodationId = 1
        };

        var result = await controller.CreateBooking(dto);

        Assert.IsInstanceOfType(result, typeof(OkResult));
    }
}
