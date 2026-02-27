using System.Net.Http.Json;
using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Services
{
    public class UserService : IUserGetAll, IUserGetById
    {
        private readonly HttpClient _httpClient;

        public UserService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<List<UserDto>> GetAllUsersAsync()
        {
            // vores client razor pages henter JSON fra endpoint her, vi bruger en absolut URL, der er mindre fleksibel end en relativ URL som "BaseAdress"
            // Men da vi bruger så få og så simpel API som vi gør her, så er det ikke et problem i vores tilfælde
            return await _httpClient.GetFromJsonAsync<List<UserDto>>("https://localhost:7026/api/user");
        }

        public async Task<UserDto?> GetUserByIdAsync(int userId)
        {
            return await _httpClient.GetFromJsonAsync<UserDto?>($"https://localhost:7026/api/user/{userId}");
        }

        public async Task<UserDto> UpdateUser(UserDto userDto)
        {
            var response = await _httpClient.PutAsJsonAsync("https://localhost:7026/api/user", userDto);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<UserDto>();
        }
    }
}
