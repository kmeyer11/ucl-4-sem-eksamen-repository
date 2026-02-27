using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models
{
    public class BookingNotification
    {
        public string UserEmail { get; set; }
        public string UserName { get; set; }
        public int Residents { get; set; }
        public double Price { get; set; }
        public DateTime CheckInDate { get; set; }
        public DateTime CheckOutDate { get; set; }
        public string AccommodationName { get; set; } = string.Empty;
        public int BookingResidents { get; set; }
    }
}
