using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Danplanner.Client.Pages.Admin
{
    [Authorize(Roles = "Admin")]
    public class UsersModel : PageModel
    {

        private readonly IUserGetAll _userGetAll;
        private readonly IUserGetById _userGetById;
        private readonly IUserUpdate _userUpdate;
        private readonly IUserDelete _userDelete;

        public UsersModel(IUserGetAll userGetAll, IUserGetById userGetById, IUserUpdate userUpdate, IUserDelete userDelete)
        {
            _userGetAll = userGetAll;
            _userGetById = userGetById;
            _userUpdate = userUpdate;
            _userDelete = userDelete;
        }

        [BindProperty]
        public UserDto SelectedUser { get; set; } = new UserDto();

        public List<UserDto> GridData { get; set; } = new List<UserDto>();

        // Henter alle brugere til visning i grid, den bliver kørt i html koden så har derfor ingen klassiske "references"
        public async Task OnGetAsync(int? id)
        {
            GridData = await _userGetAll.GetAllUsersAsync();

            if (id.HasValue)
            {
                SelectedUser = await _userGetById.GetUserByIdAsync(id.Value);
            }
        }
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                GridData = await _userGetAll.GetAllUsersAsync();
                return Page();
            }

            await _userUpdate.UpdateUserAsync(SelectedUser);
            return RedirectToPage("/Admin/Users");
        }

        public async Task<IActionResult> OnPostDeleteAsync()
        {
            await _userDelete.DeleteUserAsync(SelectedUser.UserId);
            return RedirectToPage("/Admin/Users");
        }

    }
}
