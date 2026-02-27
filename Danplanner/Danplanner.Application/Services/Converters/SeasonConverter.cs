using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Services.Converters
{
    public class SeasonConverter : ISeasonConverter
    {
        public SeasonDto ToDto(Season entity) => new SeasonDto
        {
            SeasonId = entity.SeasonId,
            SeasonName = entity.SeasonName,
            SeasonStartDate = entity.SeasonStartDate,
            SeasonEndDate = entity.SeasonEndDate,
            SeasonMultiplier = entity.SeasonMultiplier
        };

        public Season ToEntity(SeasonDto dto) => new Season
        {
            SeasonId = dto.SeasonId,
            SeasonName = dto.SeasonName,
            SeasonStartDate = dto.SeasonStartDate,
            SeasonEndDate = dto.SeasonEndDate,
            SeasonMultiplier = dto.SeasonMultiplier
        };
    }
}
