using Microsoft.Extensions.Caching.Memory;

namespace Danplanner.Application.Services
{
    public class InMemoryBruteForceCache
    {
        private readonly IMemoryCache _cache;

        public InMemoryBruteForceCache(IMemoryCache cache)
        {
            _cache = cache;
        }

        public int GetFailedAttempts(string username)
        {
            _cache.TryGetValue(AttemptsKey(username), out int count);
            return count;
        }

        public void IncreaseFailedAttempts(string username, TimeSpan expire)
        {
            var count = GetFailedAttempts(username) + 1;
            _cache.Set(AttemptsKey(username), count, expire);
        }

        public void SetLockedOut(string username, TimeSpan duration)
        {
            _cache.Set(LockoutKey(username), true, duration);
        }

        public bool IsLockedOut(string username)
        {
            return _cache.TryGetValue(LockoutKey(username), out bool _);
        }

        public void ResetAttempts(string username)
        {
            _cache.Remove(AttemptsKey(username));
            _cache.Remove(LockoutKey(username));
        }

        private static string AttemptsKey(string username) => $"attempts:{username}";
        private static string LockoutKey(string username) => $"lockout:{username}";
    }
}
