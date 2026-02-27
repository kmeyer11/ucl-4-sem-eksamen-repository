using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.AccommodationInterfaces
{
    public interface IAccommodationGetById2
    {
        Task <AccommodationDto> AccommodationGetByIdAsync(int id);
    }
}
