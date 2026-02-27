using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages.Admin
{
    [Authorize(Roles = "Admin")]
    public class AddonsModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}
