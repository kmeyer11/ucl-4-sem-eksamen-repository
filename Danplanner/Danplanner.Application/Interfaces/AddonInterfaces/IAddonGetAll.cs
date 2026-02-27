using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.AddonInterfaces
{
    public interface IAddonGetAll
    {
        Task<List<AddonDto>> GetAllAddonsAsync();
    }
}
