using System.Net.Http.Json;
using Danplanner.Application.Interfaces.ConfirmationInterfaces;
using Danplanner.Application.Interfaces.SeasonInterfaces;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Services
{
    public class SeasonService :ISeasonGetForDate, ISeasonDelete, ISeasonUpdate, ISeasonAdd, ISeasonGetById, ISeasonGetAll
    {
        private readonly HttpClient _httpClient;

        public SeasonService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<List<SeasonDto>> GetAllSeasonsAsync()
        {
            return await _httpClient.GetFromJsonAsync<List<SeasonDto>>("https://localhost:7026/api/season");
        }

        public async Task<SeasonDto?> GetSeasonByIdAsync(int seasonId)
        {
            return await _httpClient.GetFromJsonAsync<SeasonDto?>($"https://localhost:7026/api/season/{seasonId}");
        }

        public async Task<SeasonDto> AddSeasonAsync(SeasonDto seasonDto)
        {
            var response = await _httpClient.PostAsJsonAsync("https://localhost:7026/api/season", seasonDto);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<SeasonDto>();
        }

        public async Task<SeasonDto> UpdateSeasonAsync(SeasonDto seasonDto)
        {
            var response = await _httpClient.PutAsJsonAsync("https://localhost:7026/api/season", seasonDto);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<SeasonDto>();
        }

        public async Task DeleteSeasonAsync(int seasonId)
        {
            var response = await _httpClient.DeleteAsync($"https://localhost:7026/api/season/{seasonId}");
            response.EnsureSuccessStatusCode();
        }
        public async Task<SeasonDto?> GetSeasonForDate(DateTime date)
        {
            string dateString = date.ToString("yyyy-MM-dd");
            return await _httpClient.GetFromJsonAsync<SeasonDto?>($"https://localhost:7026/api/season/date/{dateString}");
        }

    }
}
