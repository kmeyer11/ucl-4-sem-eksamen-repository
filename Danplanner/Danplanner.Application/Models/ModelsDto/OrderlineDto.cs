using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models.ModelsDto
{
    public class OrderlineDto
    {
        public decimal TotalPrice { get; set; }
        public int BookingId { get; set; }
    }
}
