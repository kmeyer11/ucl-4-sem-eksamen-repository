using System.ComponentModel.DataAnnotations;

namespace Danplanner.Application.Models.ModelsDto
{
    public class AdminDto
    {
        [Key]
        public int AdminId { get; set; }
        public string? AdminDtoPassword { get; set; }
    }
}
