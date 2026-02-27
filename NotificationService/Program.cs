using System.Net.Mail;
using System.Net;
using NotificationService.Models;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPost("/orderNotify", (OrderConfirmation order) =>
{
    Console.WriteLine($"[Notification] Order -> {order.UserEmail}");

    var message = new MailMessage("danplanner.service@gmail.com", order.UserEmail)
    {
        Subject = "Booking Confirmation",
        Body = $@"
Kære {order.UserName},

Vi har modtaget din booking.

Check In : {order.CheckInDate:d}
Check Ud : {order.CheckOutDate:d}

Vi glæder os til at se dig.
"
    };

    using var smtp = new SmtpClient()
    {
        Host = "smtp.gmail.com",
        Port = 587,
        EnableSsl = true,
        Credentials = new NetworkCredential("danplanner.service@gmail.com", "ecsd ulec qzss fmsj"),
        DeliveryMethod = SmtpDeliveryMethod.Network,
        UseDefaultCredentials = false
    };

    try
    {
        smtp.Send(message);
        Console.WriteLine($"[Notification] Email sent to {order.UserEmail}");
        return Results.Ok(new {success  = true});
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Notification] Email FAILED: {ex.Message}");
        return Results.StatusCode(500);
    }

    return Results.Ok();
});

app.MapPost("/paymentNotify", (PaymentConfirmation payment) =>
{
    Console.WriteLine($"[Notification] Payment -> {payment.UserEmail}");

    var message = new MailMessage("danplanner.service@gmail.com", payment.UserEmail)
    {
        Subject = "Faktura",
        Body = $@"
Tak for din betaling.

Dato : {payment.Date:d}
Beløb: {payment.Price}

En faktura er hermed sendt.
"
    };

    using var smtp = new SmtpClient()
    {
        Host = "smtp.gmail.com",
        Port = 587,
        EnableSsl = true,
        Credentials = new NetworkCredential("danplanner.service@gmail.com", "ecsd ulec qzss fmsj"),
        DeliveryMethod = SmtpDeliveryMethod.Network,
        UseDefaultCredentials = false
    };

    try
    {
        smtp.Send(message);
        Console.WriteLine($"[Notification] Email sent to {payment.UserEmail}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Notification] Email FAILED: {ex.Message}");
    }

    return Results.Ok();
});

app.MapGet("/health", () => Results.Ok("OK"));

app.Run();

public record Notification(string Message);
