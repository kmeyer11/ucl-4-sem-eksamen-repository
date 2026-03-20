namespace SecurityMonitorService.Models
{
    public class SecurityAnalysisResult
    {
        // 0 = normal, 1 = low, 2 = medium, 3 = high, 4 = critical
        public int SeverityLevel { get; set; }
        public string AttackType { get; set; } = "";
        public string Summary { get; set; } = "";
        public string Recommendation { get; set; } = "";
    }
}
