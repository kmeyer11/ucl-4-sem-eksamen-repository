using Danplanner.Application.Interfaces.BruteForceDetectionInterfaces;

namespace Danplanner.Application.Services
{
    public class BruteForceService : IBruteForceDetection
    {
        private readonly InMemoryBruteForceCache _cache;

        private int MaxFailedAttempts = 3;
        private TimeSpan LockoutDuration = TimeSpan.FromMinutes(10);
        private TimeSpan AttemptWindow = TimeSpan.FromMinutes(10);

        public BruteForceService(InMemoryBruteForceCache cache)
        {
            _cache = cache;
        }

        public bool IsLockedOut(string username)
        {
            return _cache.IsLockedOut(username);
        }

        public void RecordFailedAttempt(string username)
        {
            _cache.IncreaseFailedAttempts(username, AttemptWindow);

            if (_cache.GetFailedAttempts(username) > MaxFailedAttempts)
            {
                _cache.SetLockedOut(username, LockoutDuration);
            }
        }

        public void RecordSuccessfulLogin(string username)
        {
            _cache.ResetAttempts(username);            
        }
    }
}