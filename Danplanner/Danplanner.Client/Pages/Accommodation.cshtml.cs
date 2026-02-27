using System.Globalization;
using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Application.Models;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Application.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages
{
    public class AccommodationModel : PageModel
    {
        private readonly IAccommodationTransfer _accommodationService;
        private readonly IWebHostEnvironment _env;
        public ContactInformation ContactInformation { get; set; }

        public AccommodationModel(IAccommodationTransfer accommodationService, IWebHostEnvironment env)
        {
            _accommodationService = accommodationService;
            _env = env;
        }

        [BindProperty(SupportsGet = true)]
        public string? Start { get; set; }

        [BindProperty(SupportsGet = true)]
        public string? End { get; set; }

        [BindProperty(SupportsGet = true)]
        public int? DaysQuery { get; set; }

        public string StartDisplay { get; private set; } = "—";
        public string EndDisplay { get; private set; } = "—";
        public int Days { get; private set; }

        public List<AccommodationDto> Items { get; private set; } = new();

        public async Task OnGetAsync()
        {
            var filePath = Path.Combine(_env.WebRootPath ?? string.Empty, "data", "contactinfo.txt");
            ContactInformation = ContactInfoReader.Load(filePath); 
            
            DateTime? startDt = ParseDate(Start, out var startDisp);
            DateTime? endDt = ParseDate(End, out var endDisp);

            StartDisplay = startDisp;
            EndDisplay = endDisp;

            if (startDt.HasValue && endDt.HasValue)
            {
                var computed = Math.Max(0, (endDt.Value.Date - startDt.Value.Date).Days);
                Days = DaysQuery ?? computed;
            }
            else if (DaysQuery.HasValue)
            {
                Days = DaysQuery.Value;
            }

            Items = (await _accommodationService
                .GetAccommodationsAsync(startDt, endDt))
                .ToList();
        }

        private static DateTime? ParseDate(string? raw, out string display)
        {
            display = "—";
            if (string.IsNullOrEmpty(raw))
                return null;

            if (DateTime.TryParseExact(
                    raw,
                    "yyyy-MM-dd",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out var dt))
            {
                display = dt.ToString("d. MMMM", CultureInfo.GetCultureInfo("da-DK"));
                return dt.Date;
            }

            display = raw;
            return null;
        }

        public IActionResult OnPostSelect(string key, string? category, string? Start, string? End)
        {
            if (!string.IsNullOrEmpty(key))
            {
                var options = new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddDays(30),
                    Path = "/"
                };
                Response.Cookies.Append("selectedItem", key, options);
            }

            var cat = category;
            if (string.IsNullOrWhiteSpace(cat) && !string.IsNullOrWhiteSpace(key))
            {
                var t = key.ToLowerInvariant();
                if (t.Contains("luksus")) cat = "luksushytte";
                else if (t.Contains("hytte")) cat = "hytte";
                else if (t.Contains("plads")) cat = "plads";
            }

            if (!string.IsNullOrEmpty(cat))
            {
                var options = new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddDays(30),
                    Path = "/"
                };
                Response.Cookies.Append("selectedCategory", cat.ToLowerInvariant(), options);
            }

            var qs = string.Empty;
            if (!string.IsNullOrEmpty(Start)) qs += $"?Start={Uri.EscapeDataString(Start)}";
            if (!string.IsNullOrEmpty(End)) qs += (qs == "" ? "?" : "&") + $"End={Uri.EscapeDataString(End)}";

            return Redirect($"/Map{qs}");
        }
    }
}
