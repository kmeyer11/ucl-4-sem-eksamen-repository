namespace SecurityMonitorService.Models
{
    public class LogEntry
    {
        public int LogId { get; set; }
        public string LogType { get; set; } = "";
        public string LogDescription { get; set; } = "";
        public DateTime LogTimeStamp { get; set; }
        public string? AffectedEmail { get; set; }
        public string? IpAddress { get; set; }
    }
}
