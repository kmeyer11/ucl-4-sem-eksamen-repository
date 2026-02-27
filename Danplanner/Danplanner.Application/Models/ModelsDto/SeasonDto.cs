using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models.ModelsDto
{
    public class SeasonDto
    {
        public int SeasonId { get; init; }

        [Required]
        public string SeasonName { get; init; } = string.Empty;

        [Required]
        public DateTime SeasonStartDate { get; init; }

        [Required]
        public DateTime SeasonEndDate { get; init; }

        [Range(0.1, 5.0)]
        public decimal SeasonMultiplier { get; init; }
    }
}
