using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserGetAll
    {
        Task<List<UserDto>> GetAllUsersAsync();
    }
}
