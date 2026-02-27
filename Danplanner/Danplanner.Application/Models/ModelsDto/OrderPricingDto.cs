using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models.ModelsDto
{
    public class OrderPricingDto
    {
        public int Days { get; init; }
        public decimal TotalPrice { get; init; }
        public decimal AddonsTotal { get; init; }
        public string TotalPriceDisplay { get; init; } = string.Empty;
        public AccommodationDto? SelectedAccommodation { get; init; }
        public List<AddonDto> Addons { get; init; } = [];
    }
}
