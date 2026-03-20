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

        // Kør analyse hvert 5. minut
        private readonly TimeSpan _interval = TimeSpan.FromMinutes(5);

        // Kig kun på logs fra de seneste 15 minutter
        private readonly TimeSpan _lookbackWindow = TimeSpan.FromMinutes(15);

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
            var since = DateTime.UtcNow - _lookbackWindow;

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

            _logger.LogInformation("[SecurityMonitor] Sværhedsgrad={level}, Angrebstype={type}",
                result.SeverityLevel, result.AttackType);

            var alertCooldownExpired = DateTime.UtcNow - _lastAlertSent > _alertCooldown;

            if (result.SeverityLevel >= 2 && alertCooldownExpired)
            {
                await _analysisService.SendAlertEmailAsync(result);
                _lastAlertSent = DateTime.UtcNow;
            }
        }
    }
}
