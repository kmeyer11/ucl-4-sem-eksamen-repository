using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        [Required]
        public string UserAdress { get; set; }
        public string? UserMobile { get; set; }
        [Required]
        public string UserEmail { get; set; }
        public string? UserName { get; set; }
    }
}
