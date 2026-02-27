using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Interfaces.UserInterfaces
{
    public interface IUserGetByEmail
    {
        Task<UserDto?> GetUserByEmailAsync(string userEmail);
    }
}
