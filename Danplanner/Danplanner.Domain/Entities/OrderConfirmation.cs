using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class OrderConfirmation
    {
        [Key]
        public int OrderConfirmationId { get; set; }
        public string UserEmail { get; set; }
        public string UserName { get; set; }
        public DateTime OrderConfirmationDate { get; set; }
        public DateTime CheckInDate { get; set; }
        public DateTime CheckOutDate { get; set; }
    }
}
