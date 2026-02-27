using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using Danplanner.Application.Interfaces.SeasonInterfaces;

namespace Danplanner.Persistence.Repositories.SeasonRepositories
{
    public class SeasonRepositoryPost : ISeasonAdd
    {
        private readonly DbManager _dbManager;

        public SeasonRepositoryPost(DbManager dbManager)
        {
            _dbManager = dbManager;
        }
        public async Task<SeasonDto> AddSeasonAsync(SeasonDto seasonDto)
        {
            var season = new Season
            {
                SeasonName = seasonDto.SeasonName,
                SeasonStartDate = seasonDto.SeasonStartDate,
                SeasonEndDate = seasonDto.SeasonEndDate,
                SeasonMultiplier = seasonDto.SeasonMultiplier
            };

            await _dbManager.Season.AddAsync(season);
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
