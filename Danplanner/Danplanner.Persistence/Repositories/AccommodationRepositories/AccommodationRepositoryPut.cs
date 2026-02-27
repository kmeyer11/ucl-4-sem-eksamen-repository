using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Persistence.DbMangagerDir;
using Microsoft.EntityFrameworkCore;

namespace Danplanner.Persistence.Repositories.AccommodationRepositories
{
    public class AccommodationRepositoryPut : IAccommodationUpdate
    {
        private readonly DbManager _db;

        public AccommodationRepositoryPut(DbManager db)
        {
            _db = db;
        }

        public async Task MarkUnavailableAsync(int accommodationId)
        {
            var entity = await _db.Accommodation
                .FirstOrDefaultAsync(a => a.AccommodationId == accommodationId);

            if (entity == null)
                return;

            entity.Availability = 0;
            await _db.SaveChangesAsync();
        }
    }
}
