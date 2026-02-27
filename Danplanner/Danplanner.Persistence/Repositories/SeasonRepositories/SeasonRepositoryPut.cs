using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using Microsoft.EntityFrameworkCore;
using Danplanner.Application.Interfaces.SeasonInterfaces;

namespace Danplanner.Persistence.Repositories.SeasonRepositories
{
    public class SeasonRepositoryPut : ISeasonUpdate
    {
        private readonly DbManager _dbManager;

        public SeasonRepositoryPut(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<SeasonDto?> UpdateSeasonAsync(SeasonDto seasonDto)
        {
            var season = await _dbManager.Season.FirstOrDefaultAsync(u => u.SeasonId == seasonDto.SeasonId);
            if (season == null) return null;

            season.SeasonName = seasonDto.SeasonName;
            season.SeasonStartDate = seasonDto.SeasonStartDate;
            season.SeasonEndDate = seasonDto.SeasonEndDate;
            season.SeasonMultiplier = seasonDto.SeasonMultiplier;

            await _dbManager.SaveChangesAsync();

            return new SeasonDto
            {
                SeasonId = season.SeasonId,
                SeasonName = season.SeasonName,
                SeasonStartDate = season.SeasonStartDate,
                SeasonEndDate = season.SeasonEndDate,
                SeasonMultiplier = season.SeasonMultiplier
            };
        }
    }
}
