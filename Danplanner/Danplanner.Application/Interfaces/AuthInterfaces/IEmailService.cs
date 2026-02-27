namespace Danplanner.Application.Interfaces.AuthInterfaces
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
    }
}
