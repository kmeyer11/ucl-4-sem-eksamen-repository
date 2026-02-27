using Danplanner.Domain.Entities;

namespace Danplanner.Application.Interfaces.AccommodationInterfaces
{
    public interface IAccommodationGetAll
    {
        Task<List<Accommodation>> GetAllAccommodationsAsync();
    }
}
