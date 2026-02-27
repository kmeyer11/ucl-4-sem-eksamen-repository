using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Application.Services;
using Danplanner.Domain.Entities;
using Moq;
namespace Danplanner.test
{
    [TestClass]
    public class PriceCalculatorTests
    {
        [TestMethod]
        public async Task PriceCalculatorTest()
        {
            var addonService = new Mock<IAddonGetAll>();
            addonService.Setup(x => x.GetAllAddonsAsync())
                .ReturnsAsync(new List<AddonDto>
                {
                    new AddonDto { AddonId = 1, AddonPrice = 100 },
                    new AddonDto { AddonId = 2, AddonPrice = 200 }
                });

            var accommodationService = new Mock<IAccommodationGetAll>();
            accommodationService.Setup(x => x.GetAllAccommodationsAsync())
                .ReturnsAsync(new List<Accommodation>
                {
                    new Accommodation { AccommodationId = 1, PricePerNight = 100 },
                });

            var converter = new Mock<IAccommodationConverter>();
            converter.Setup(x => x.AccommodationDtoConverter(It.IsAny<List<Accommodation>>()))
                .ReturnsAsync(new List<AccommodationDto>
                {
                    new AccommodationDto { AccommodationId = 1, PricePerNight = 100 }
                });

            var seasonService = new Mock<ISeasonGetForDate>();
            seasonService.Setup(x => x.GetSeasonForDate(It.IsAny<DateTime>()))
                .ReturnsAsync((SeasonDto?)null);

            var calculator = new OrderPricingService(addonService.Object, accommodationService.Object, converter.Object, seasonService.Object);

            int accommodationId = 1;
            var selectedAddonIds = new List<int> { 1, 2 };
            DateTime checkIn = new DateTime(2025, 1, 1);
            DateTime checkOut = new DateTime(2025, 1, 4);
            int guests = 2;

            var result = await calculator.CalculateAsync(accommodationId, selectedAddonIds, checkIn, checkOut, guests);

            Assert.AreEqual(3, result.Days);        // 3 dage
            Assert.AreEqual(300m, result.AddonsTotal); // 100 + 200
            Assert.AreEqual(650m, result.TotalPrice);  // 100*3 + (2-1)*50 + 300
        }
    }
}
