using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserGetById
    {
        Task<UserDto> GetUserByIdAsync(int userId);
    }
}
