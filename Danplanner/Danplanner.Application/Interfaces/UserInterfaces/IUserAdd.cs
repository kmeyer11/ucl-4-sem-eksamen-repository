using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserAdd
    {
        Task AddUserAsync(UserDto userDto);
    }
}
