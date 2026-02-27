using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using Microsoft.EntityFrameworkCore;

namespace Danplanner.Persistence.Repositories.SeasonRepositories
{

    public class SeasonRepositoryGet : ISeasonGetAll, ISeasonGetById, ISeasonGetForDate
    {
        private readonly DbManager _dbManager;

        public SeasonRepositoryGet(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<List<SeasonDto>> GetAllSeasonsAsync()
        {
            return await _dbManager.Season
        .Select(s => new SeasonDto
        {
            SeasonId = s.SeasonId,
            SeasonName = s.SeasonName,
            SeasonStartDate = s.SeasonStartDate,
            SeasonEndDate = s.SeasonEndDate,
            SeasonMultiplier = s.SeasonMultiplier
        }).ToListAsync();
        }

        public async Task<SeasonDto?> GetSeasonByIdAsync(int seasonId)
        {
            var season = await _dbManager.Season.FirstOrDefaultAsync(u => u.SeasonId == seasonId);
            if (season == null) return null;
            return new SeasonDto
            {
                SeasonId = season.SeasonId,
                SeasonName = season.SeasonName,
                SeasonStartDate = season.SeasonStartDate,
                SeasonEndDate = season.SeasonEndDate,
                SeasonMultiplier = season.SeasonMultiplier
            };
        }

        public async Task<SeasonDto?> GetSeasonForDate(DateTime date)
        {
            var season = await _dbManager.Season
                .FirstOrDefaultAsync(s => date >= s.SeasonStartDate && date <= s.SeasonEndDate);

            if (season == null)
            {
                return null;
            }

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
