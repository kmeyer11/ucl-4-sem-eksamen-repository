using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.AccommodationInterfaces
{
    public interface IAccommodationTransfer
    {
        Task<IReadOnlyList<AccommodationDto>> GetAccommodationsAsync
        (
            DateTime? start,
            DateTime? end
        );
    }
}
