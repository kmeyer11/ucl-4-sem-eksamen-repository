using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Payment
    {
        [Key]
        public int PaymentId { get; set; }
        [Required]
        public bool PaymentStatus { get; set; }
    }
}
