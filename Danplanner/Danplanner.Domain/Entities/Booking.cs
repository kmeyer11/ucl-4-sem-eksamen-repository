using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Booking
    {
        [Key]
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
