using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace Danplanner.Infrastructure.Services
{
    public class InMemoryBruteForceCache
    {
        private readonly InMemoryBruteForceCache _cache;

        public InMemoryBruteForceCache(InMemoryBruteForceCache cache)
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
            return _cache.TryGetValue(LockedoutKey(username), out bool _);
        }

        public void ResetAttempts(string username)
        {
            _cache.Remove(AttemptsKey(username));
            _cache.Remove(AttemptsKey(username));
        }
        
        private static string AttemptsKey(string username) => $"attempts:{username}";
        private static string LockoutKey(string username) => $"lockout:{username}";
    }
}