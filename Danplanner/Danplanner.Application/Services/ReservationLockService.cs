using Danplanner.Application.Interfaces.ReservationInterfaces;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Services
{
    internal sealed class ReservationLock
    {
        public string Token { get; init; } = "";
        public string Owner { get; init; } = "";
        public DateTime ExpiresAt { get; init; }
    }

    public class ReservationLockService : IReservationLockService
    {
        private readonly IMemoryCache _cache;
        private readonly object _sync = new();

        public ReservationLockService(IMemoryCache cache)
        {
            _cache = cache;
        }

        public Task<(bool Success, string Token, DateTime ExpiresAt, string Message)> TryLockAsync(string key, TimeSpan ttl, string owner)
        {
            var cacheKey = $"reservation:lock:{key}";
            lock (_sync)
            {
                if (_cache.TryGetValue(cacheKey, out ReservationLock existing))
                {
                    if (existing.ExpiresAt > DateTime.UtcNow)
                        return Task.FromResult((false, "", existing.ExpiresAt, "Already locked"));
                    // expired entry — fall through to replace
                }

                var token = Guid.NewGuid().ToString("N");
                var expires = DateTime.UtcNow.Add(ttl);
                var entry = new ReservationLock { Token = token, Owner = owner, ExpiresAt = expires };
                _cache.Set(cacheKey, entry, expires);
                return Task.FromResult((true, token, expires, "Locked"));
            }
        }

        public Task<bool> ValidateTokenAsync(string key, string token)
        {
            var cacheKey = $"reservation:lock:{key}";
            if (_cache.TryGetValue(cacheKey, out ReservationLock entry) && entry.Token == token && entry.ExpiresAt > DateTime.UtcNow)
                return Task.FromResult(true);
            return Task.FromResult(false);
        }

        public Task ReleaseLockAsync(string key, string token)
        {
            var cacheKey = $"reservation:lock:{key}";
            lock (_sync)
            {
                if (_cache.TryGetValue(cacheKey, out ReservationLock entry) && entry.Token == token)
                {
                    _cache.Remove(cacheKey);
                }
            }
            return Task.CompletedTask;
        }

        public Task<bool> IsLockedAsync(string key)
        {
            var cacheKey = $"reservation:lock:{key}";
            if (_cache.TryGetValue(cacheKey, out ReservationLock entry) && entry.ExpiresAt > DateTime.UtcNow)
                return Task.FromResult(true);
            return Task.FromResult(false);
        }
    }
}
