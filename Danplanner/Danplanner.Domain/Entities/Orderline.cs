using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Orderline
    {
        [Key]
        public int OrderlineId { get; set; }
        public decimal TotalPrice { get; set; }
        public int BookingId { get; set; }
    }
}
