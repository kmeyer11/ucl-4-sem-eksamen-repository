using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class PaymentConfirmation
    {
        [Key]
        public int PaymentConfirmationId { get; set; }
        public DateTime PaymentConfirmationDate { get; set; }
        public int? PaymentId { get; set; }
        public int OrderlineId { get; set; }
    }
}
