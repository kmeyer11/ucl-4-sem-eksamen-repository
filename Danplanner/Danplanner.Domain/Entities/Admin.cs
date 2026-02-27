using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Admin
    {
        [Key]
        public int AdminId { get; set; }
        public string? AdminPassword { get; set; }
    }
}
