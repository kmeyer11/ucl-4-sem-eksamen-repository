using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Services
{
    public class AccommodationService : IAccommodationTransfer, IAccommodationConverter
    {
        private readonly IAccommodationGetAllFromTxt _repository;

        public AccommodationService(IAccommodationGetAllFromTxt repository)
        {
            _repository = repository;
        }

        private static string? CategoryFromName(string name)
        {
            var n = (name ?? string.Empty).ToLowerInvariant();

            if (n.Contains("luksus")) return "luksushytte";
            if (n.Contains("hytte")) return "hytte";
            if (n.Contains("plads")) return "plads";
            return null;
        }

        public async Task<IReadOnlyList<AccommodationDto>> GetAccommodationsAsync(
            DateTime? start,
            DateTime? end)
        {
            var entities = await _repository.GetAccommodationsFromTxtAsync();

            return entities.Select(a => new AccommodationDto
            {
                AccommodationId = a.AccommodationId,
                AccommodationName = a.AccommodationName,
                AccommodationDescription = a.AccommodationDescription,
                PricePerNight = a.PricePerNight,
                ImageUrl = a.ImageUrl ?? "/images/default.png",
                Availability = a.Availability,
                Category = !string.IsNullOrWhiteSpace(a.Category)
                    ? a.Category.ToLowerInvariant()
                    : CategoryFromName(a.AccommodationName)
            }).ToList();
        }

        public async Task<List<AccommodationDto>> AccommodationDtoConverter(List<Accommodation> accommodations)
        {
            List<AccommodationDto> list = new List<AccommodationDto>();

            foreach (var accommodation in accommodations)
            {
                AccommodationDto newAccommodationDto = new AccommodationDto
                {
                    AccommodationId = accommodation.AccommodationId,
                    AccommodationName = accommodation.AccommodationName,
                    AccommodationDescription = accommodation.AccommodationDescription,
                    PricePerNight = accommodation.PricePerNight,
                    Availability = accommodation.Availability,
                };

                list.Add(newAccommodationDto);
            }
            return list;
        }
    }
}
