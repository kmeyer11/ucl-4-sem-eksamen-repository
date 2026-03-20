using Dapper;
using MySqlConnector;
using SecurityMonitorService.Models;

namespace SecurityMonitorService.Services
{
    public class LogMonitorBackgroundService : BackgroundService
    {
        private readonly IConfiguration _config;
        private readonly SecurityAnalysisService _analysisService;
        private readonly ILogger<LogMonitorBackgroundService> _logger;

        private DateTime _lastAlertSent = DateTime.MinValue;
        private DateTime _lastChecked = DateTime.UtcNow;

        // Kør analyse hvert minut
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(1);

        // Minimum 1 time mellem alarmer så vi ikke spam-mailer
        private readonly TimeSpan _alertCooldown = TimeSpan.FromHours(1);

        public LogMonitorBackgroundService(
            IConfiguration config,
            SecurityAnalysisService analysisService,
            ILogger<LogMonitorBackgroundService> logger)
        {
            _config = config;
            _analysisService = analysisService;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[SecurityMonitor] Startet. Analyserer hvert {min} minutter.", _interval.TotalMinutes);

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(_interval, stoppingToken);

                try
                {
                    await RunAnalysisCycleAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SecurityMonitor] Fejl under analysecyklus.");
                }
            }
        }

        private async Task RunAnalysisCycleAsync()
        {
            var connString = _config.GetConnectionString("Default");
            var since = _lastChecked;
            _lastChecked = DateTime.UtcNow;

            List<LogEntry> logs;

            await using (var conn = new MySqlConnection(connString))
            {
                logs = (await conn.QueryAsync<LogEntry>(
                    @"SELECT LogId, LogType, LogDescription, LogTimeStamp, AffectedEmail, IpAddress
                      FROM Log
                      WHERE LogTimeStamp >= @since
                      ORDER BY LogTimeStamp DESC",
                    new { since }
                )).ToList();
            }

            if (logs.Count == 0)
            {
                _logger.LogInformation("[SecurityMonitor] Ingen nye logs, springer over.");
                return;
            }

            _logger.LogInformation("[SecurityMonitor] Analyserer {count} logs...", logs.Count);

            var result = await _analysisService.AnalyzeLogsAsync(logs);

            _logger.LogInformation("[SecurityMonitor] ─────────────────────────────────");
            _logger.LogInformation("[SecurityMonitor] Sværhedsgrad : {level}/4", result.SeverityLevel);
            _logger.LogInformation("[SecurityMonitor] Angrebstype  : {type}", result.AttackType);
            _logger.LogInformation("[SecurityMonitor] Opsummering  : {summary}", result.Summary);
            _logger.LogInformation("[SecurityMonitor] Anbefaling   : {rec}", result.Recommendation);
            _logger.LogInformation("[SecurityMonitor] ─────────────────────────────────");

            var alertCooldownExpired = DateTime.UtcNow - _lastAlertSent > _alertCooldown;

            if (result.SeverityLevel >= 2 && alertCooldownExpired)
            {
                _logger.LogWarning("[SecurityMonitor] Angreb detekteret! Sender email alarm...");
                await _analysisService.SendAlertEmailAsync(result);
                _lastAlertSent = DateTime.UtcNow;
            }
            else if (result.SeverityLevel == 0)
            {
                _logger.LogInformation("[SecurityMonitor] Alt normalt, ingen alarm.");
            }
        }
    }
}
