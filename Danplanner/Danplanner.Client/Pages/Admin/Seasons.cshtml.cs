using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages.Admin
{
    [Authorize(Roles = "Admin")]
    public class SeasonsModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
