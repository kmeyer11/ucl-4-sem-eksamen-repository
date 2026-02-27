using System.Net.Http.Json;
using Danplanner.Application.Interfaces.AddonInterfaces;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Services
{
    public class AddonService : IAddonGetAll
    {
        private readonly HttpClient _httpClient;

        public AddonService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<List<AddonDto>> GetAllAddonsAsync()
        {
            return await _httpClient.GetFromJsonAsync<List<AddonDto>>("https://localhost:7026/api/addon");
        }
    }
}
