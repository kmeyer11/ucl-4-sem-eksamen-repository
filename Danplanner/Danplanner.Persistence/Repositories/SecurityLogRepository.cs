using Danplanner.Application.Interfaces.LogInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;

namespace Danplanner.Persistence.Repositories
{
    public class SecurityLogRepository : ISecurityLogger
    {
        private readonly DbManager _db;

        public SecurityLogRepository(DbManager db)
        {
            _db = db;
        }

        public async Task LogAsync(string logType, string description, string? affectedEmail = null, string? ipAddress = null)
        {
            var log = new Log
            {
                LogType = logType,
                LogDescription = description,
                LogTimeStamp = DateTime.UtcNow,
                AffectedEmail = affectedEmail,
                IpAddress = ipAddress
            };

            _db.Log.Add(log);
            await _db.SaveChangesAsync();
        }
    }
}
