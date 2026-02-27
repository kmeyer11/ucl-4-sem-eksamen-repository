using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.ConfirmationInterfaces
{
    public interface IOrderPricing
    {
        Task<OrderPricingDto> CalculateAsync
        (
            int accommodationId,
            List<int> selectedAddonIds,
            DateTime? checkIn,
            DateTime? checkOut,
            int numberOfGuests
        );
    }
}
