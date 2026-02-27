using Danplanner.Application.Interfaces.UserInterfaces;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Mvc;

namespace Danplanner.Client.Controllers
{
    [ApiController]
    [Route("api/user/[controller]")] // vores route bliver api/user
    public class UserController : ControllerBase
    {
        private readonly IUserGetAll _getAll;
        private readonly IUserGetById _getById;
        private readonly IUserUpdate _update;
        private readonly IUserDelete _userDelete;

        public UserController(IUserGetAll getAll, IUserGetById getById, IUserUpdate update, IUserDelete userDelete)
        {
            _getAll = getAll;
            _getById = getById;
            _update = update;
            _userDelete = userDelete;
        }

        [HttpGet]
        public async Task<ActionResult<List<UserDto>>> GetUsers()
        {
            var users = await _getAll.GetAllUsersAsync();
            return Ok(users);
            // vi returnerer 200 OK med listen af users
        }

        [HttpGet("{id:int}")]
        public async Task<ActionResult<UserDto?>> GetUserById(int id)
        {
            var user = await _getById.GetUserByIdAsync(id);
            if (user == null) return NotFound();
            return Ok(user);
        }

        [HttpPut("{id:int}")]
        public async Task<ActionResult<UserDto>> UpdateUser(int id, [FromBody] UserDto userDto)
        {
            userDto.UserId = id; // sikre at id i URL og body er ens

            var updatedUser = await _update.UpdateUserAsync(userDto);
            if (updatedUser == null) return NotFound();
            return Ok(updatedUser);
        }

        [HttpDelete("{id:int}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            await _userDelete.DeleteUserAsync(id);
            return NoContent(); // Returner 204 No Content ved succesfuld sletning
        }
    }
}
