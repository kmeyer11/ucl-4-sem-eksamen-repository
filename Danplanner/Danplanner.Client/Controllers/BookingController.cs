using Danplanner.Application.Interfaces.BookingInterfaces;
using Danplanner.Application.Models;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Mvc;

namespace Danplanner.Client.Controllers
{
    [ApiController]
    [Route("api/booking/[controller]")]
    public class BookingController : ControllerBase
    {
        private readonly IBookingAdd _bookingAdd;

        public BookingController(IBookingAdd bookingAdd)
        {
            _bookingAdd = bookingAdd;
        }

        [HttpPost]
        public async Task<ActionResult> CreateBooking([FromBody] BookingDto bookingDto)
        {
            await _bookingAdd.AddBookingAsync(bookingDto);
            return Ok();
        }
    }
}
