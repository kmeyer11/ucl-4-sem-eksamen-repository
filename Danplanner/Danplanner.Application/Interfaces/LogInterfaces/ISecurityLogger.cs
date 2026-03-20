public interface ISecurityLogger
{
    Task LogAsync(string logType, string description, string? affectedEmail = null, string? ipAddress = null);
}