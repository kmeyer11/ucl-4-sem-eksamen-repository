using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages.Admin
{
    [Authorize(Roles = "Admin")]
    public class LogModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
