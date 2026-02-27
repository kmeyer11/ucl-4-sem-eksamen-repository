using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models
{
    public sealed class LockRequest
    {
        public int AccommodationId { get; set; } = 0;
        public string Start { get; set; } = "";
        public string End { get; set; } = "";
        public string PlaceKey { get; set; } = "";
    }
}
