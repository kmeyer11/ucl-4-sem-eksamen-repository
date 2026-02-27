using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Application.Interfaces.ConfirmationInterfaces;
using Danplanner.Application.Interfaces.SeasonInterfaces;

namespace Danplanner.Application.Services
{
    public class OrderPricingService : IOrderPricing
    {
        private readonly IAddonGetAll _addonGetAll;
        private readonly IAccommodationGetAll _accommodationGetAll;
        private readonly IAccommodationConverter _accommodationConverter;
        private readonly ISeasonGetForDate _seasonGetForDate;

        public OrderPricingService
        (
            IAddonGetAll addonGetAll,
            IAccommodationGetAll accommodationGetAll,
            IAccommodationConverter accommodationConverter,
            ISeasonGetForDate seasonGetForDate)
        {
            _addonGetAll = addonGetAll;
            _accommodationGetAll = accommodationGetAll;
            _accommodationConverter = accommodationConverter;
            _seasonGetForDate = seasonGetForDate;
        }

        public async Task<OrderPricingDto> CalculateAsync
        (
            int accommodationId,
            List<int> selectedAddonIds,
            DateTime? checkIn,
            DateTime? checkOut,
            int numberofGuests)
        {
            var addons = (await _addonGetAll.GetAllAddonsAsync()).ToList();

            int days = 0;
            if (checkIn.HasValue && checkOut.HasValue)
            {
                days = Math.Max(0, (checkOut.Value.Date - checkIn.Value.Date).Days);
            }

            var accommodations = await _accommodationGetAll.GetAllAccommodationsAsync();
            var accommodationsDto = await _accommodationConverter.AccommodationDtoConverter(accommodations);
            var selectedAccommodation = accommodationsDto.FirstOrDefault(a => a.AccommodationId == accommodationId);

            decimal total = 0;

            if (selectedAccommodation?.PricePerNight is decimal price && checkIn.HasValue && checkOut.HasValue)
            {

                for (var date = checkIn.Value.Date; date < checkOut.Value.Date; date = date.AddDays(1))
                {
                    var season = await _seasonGetForDate.GetSeasonForDate(date);
                    decimal multiplier = season?.SeasonMultiplier ?? 1;
                    total += price * multiplier;
                }

                total += (numberofGuests - 1) * 50;
            }

            var addonsTotal = addons
                .Where(a => selectedAddonIds.Contains(a.AddonId))
                .Sum(a => (decimal)a.AddonPrice);

            total += addonsTotal;

            return new OrderPricingDto
            {
                Days = days,
                Addons = addons,
                AddonsTotal = addonsTotal,
                TotalPrice = total,
                SelectedAccommodation = selectedAccommodation,
                TotalPriceDisplay = $"{total:N0} kr."
            };
        }
    }
}
