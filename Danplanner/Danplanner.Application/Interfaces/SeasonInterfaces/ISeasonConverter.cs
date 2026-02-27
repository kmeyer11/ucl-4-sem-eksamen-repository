using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Domain.Entities;

namespace Danplanner.Application.Interfaces.SeasonInterfaces
{
    public interface ISeasonConverter
    {
        SeasonDto ToDto(Season entity);
        Season ToEntity(SeasonDto dto);
    }

}
