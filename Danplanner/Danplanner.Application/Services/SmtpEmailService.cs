using System.Net;
using System.Net.Mail;
using Danplanner.Application.Interfaces.AuthInterfaces;
using Microsoft.Extensions.Configuration;

namespace Danplanner.Application.Services
{
    public class SmtpEmailService : IEmailService
    {
        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUser;
        private readonly string _smtpPass;
        private readonly string _senderEmail;
        private readonly string _senderName;

        public SmtpEmailService(IConfiguration configuration)
        {
            _smtpHost = configuration["EmailSettings:SmtpHost"];
            _smtpPort = int.Parse(configuration["EmailSettings:SmtpPort"]);
            _smtpUser = configuration["EmailSettings:Username"];
            _smtpPass = configuration["EmailSettings:Password"];
            _senderEmail = configuration["EmailSettings:SenderEmail"];
            _senderName = configuration["EmailSettings:SenderName"];
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            using var client = new SmtpClient(_smtpHost, _smtpPort)
            {
                Credentials = new NetworkCredential(_smtpUser, _smtpPass),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_senderEmail, _senderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            mailMessage.To.Add(toEmail);

            await client.SendMailAsync(mailMessage);
        }
    }
}
