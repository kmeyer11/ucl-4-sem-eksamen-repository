namespace NotificationService.Models
{
    public class OrderConfirmation : Notification
    {
        public DateTime CheckInDate { get; set; }
        public DateTime CheckOutDate { get; set; }
    }
}
