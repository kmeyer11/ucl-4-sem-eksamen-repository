using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Domain.Entities
{
    public class Season
    {
        public int SeasonId { get; set; }
        public string SeasonName { get; set; } = string.Empty;
        public DateTime SeasonStartDate { get; set; }
        public DateTime SeasonEndDate { get; set; }
        public decimal SeasonMultiplier { get; set; }
    }
}
