namespace Danplanner.Application.Models
{
    public class MapPoint
    {
        public string Key { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public int? AccommodationId { get; set; }
        public string? Description { get; set; }
        public int X { get; set; }
        public int Y { get; set; }
        public string? ImageUrl { get; set; }
        public string? Category { get; set; }
    }
}
