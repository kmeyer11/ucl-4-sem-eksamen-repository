using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models.ModelsDto
{
    public class PaymentConfirmationDto : NotificationDto
    {
        public int PaymentId { get; set; }
        public int? OrderlineId { get; set; }
        public string AccommodationName { get; set; }
        public int BookingResidents { get; set; }
        public DateTime BookingCheckIn { get; set; }
        public DateTime BookingCheckOut { get; set; }
        public decimal Price { get; set; }

    }
}
