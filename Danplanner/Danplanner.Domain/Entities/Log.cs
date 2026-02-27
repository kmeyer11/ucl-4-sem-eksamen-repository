using System.ComponentModel.DataAnnotations;

namespace Danplanner.Domain.Entities
{
    public class Log
    {
        [Key]
        public int LogId { get; set; }
        [Required]
        public string LogDescription { get; set; }
        [Required]
        public DateTime LogTimeStamp { get; set; }
        public int AdminId { get; set; }
    }
}
