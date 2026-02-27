using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Addon
    {
        [Key]
        public int AddonId { get; set; }
        [Required]
        public string AddonName { get; set; }
        [Required]
        public double AddonPrice { get; set; }
        [Required]
        public string AddonDescription { get; set; }
    }
}
