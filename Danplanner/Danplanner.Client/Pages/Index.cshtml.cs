using Danplanner.Application.Interfaces.AdminInterfaces;
using Danplanner.Domain.Entities;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class IndexModel : PageModel
{
    private readonly IAdminGetAll _adminGetAll;

    public List<Admin> Admins { get; private set; } = new List<Admin>();

    public IndexModel(IAdminGetAll adminGetAll)
    {
        _adminGetAll = adminGetAll;
    }

    public async Task OnGetAsync()
    {
        Admins = await _adminGetAll.LoadAdminListAsync();
    }
}
