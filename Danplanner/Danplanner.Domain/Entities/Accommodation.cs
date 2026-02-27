using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Danplanner.Domain.Entities
{
    public class Accommodation
    {
        [Key]
        public int AccommodationId { get; set; }
        [Required]
        public string AccommodationName { get; set; } = string.Empty;
        [Required]
        public string AccommodationDescription { get; set; } = string.Empty;
        [Required]
        public decimal? PricePerNight { get; set; }
        [Required]
        public int Availability { get; set; }
        [NotMapped]
        public string? ImageUrl { get; set; }
        [NotMapped]
        public string? Category { get; set; }
    }
}
