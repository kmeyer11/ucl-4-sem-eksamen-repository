using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using Danplanner.Application.Interfaces.SeasonInterfaces;

namespace Danplanner.Persistence.Repositories.SeasonRepositories
{
    public class SeasonRepositoryDelete : ISeasonDelete
    {
        private readonly DbManager _dbManager;

        public SeasonRepositoryDelete(DbManager dbManager)
        {
            _dbManager = dbManager;
        }
        public async Task DeleteSeasonAsync(int seasonId)
        {
            var season = await _dbManager.Season.FindAsync(seasonId);
            if (season != null)
            {
                _dbManager.Season.Remove(season);
                await _dbManager.SaveChangesAsync();
            }
        }
    }
}
