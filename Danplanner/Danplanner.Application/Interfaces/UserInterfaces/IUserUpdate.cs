using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserUpdate
    {
        Task<UserDto> UpdateUserAsync(UserDto userDto);
    }
}
