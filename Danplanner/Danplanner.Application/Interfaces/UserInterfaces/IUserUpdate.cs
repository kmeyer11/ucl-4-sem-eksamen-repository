using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserUpdate
    {
        Task<UserDto?> LockUser(UserDto userDto);
        Task<UserDto> UpdateUserAsync(UserDto userDto);
    }
}
