using Danplanner.Application.Models;
using Danplanner.Application.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages
{
    public class ThankyouModel : PageModel
    {
        private readonly IWebHostEnvironment _env;
        public ContactInformation ContactInformation { get; set; }

        public ThankyouModel(IWebHostEnvironment env)
        {
            _env = env;
        }

        public void OnGet()
        {
            // Kontaktinfo boks
            var filePath = Path.Combine(_env.WebRootPath ?? string.Empty, "data", "contactinfo.txt");
            ContactInformation = ContactInfoReader.Load(filePath);
        }
    }
}
