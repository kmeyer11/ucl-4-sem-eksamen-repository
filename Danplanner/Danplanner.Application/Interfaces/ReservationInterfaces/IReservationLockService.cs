using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.ReservationInterfaces
{
    public interface IReservationLockService
    {
        Task<(bool Success, string Token, DateTime ExpiresAt, string Message)> TryLockAsync(string key, TimeSpan ttl, string owner);
        Task<bool> ValidateTokenAsync(string key, string token);
        Task ReleaseLockAsync(string key, string token);
        Task<bool> IsLockedAsync(string key);
    }
}
