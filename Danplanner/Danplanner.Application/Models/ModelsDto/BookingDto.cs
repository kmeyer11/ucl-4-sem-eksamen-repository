using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models.ModelsDto
{
    public class BookingDto
    {
        public int BookingId { get; set; }
        [Required]
        public int BookingResidents { get; set; }
        [Required]
        public double BookingPrice { get; set; }
        public DateTime CheckInDate { get; set; }
        public DateTime CheckOutDate { get; set; }
        public int UserId { get; set; }
        public int AccommodationId { get; set; }
    }
}
