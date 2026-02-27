using Danplanner.Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Infrastructure.Services
{
    public class DawaAddressService : IAddressService
    {
        private readonly HttpClient _httpClient;

        public DawaAddressService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        private class DawaResult
        {
            public string tekst { get; set; }
        }

        public async Task<List<string>> GetAddressesAsync(string query)
        {
            var requestUri = $"https://api.dataforsyningen.dk/adresser/autocomplete?q={Uri.EscapeDataString(query)}&per_side=5";
            var response = await _httpClient.GetAsync(requestUri);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var addresses = System.Text.Json.JsonSerializer.Deserialize<List<DawaResult>>(content);
            return addresses?.Select(a => a.tekst).ToList() ?? new List<string>();
        }
    }
}
