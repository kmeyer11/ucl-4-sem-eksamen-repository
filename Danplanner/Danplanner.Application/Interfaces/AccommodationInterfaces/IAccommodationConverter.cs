using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.AccommodationInterfaces
{
    public interface IAccommodationConverter
    {
        Task<List<AccommodationDto>> AccommodationDtoConverter(List<Accommodation> list);
    }
}
