namespace NotificationService.Models
{
    public class PaymentConfirmation : Notification
    {
        public int PaymentId { get; set; }
        public int? OrderlineId { get; set; }
        public string AccommodationName { get; set; }
        public int BookingResidents { get; set; }
        public DateTime BookingCheckIn { get; set; }
        public DateTime BookingCheckOut { get; set; }
        public decimal Price { get; set; }

    }
}
