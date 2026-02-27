namespace Danplanner.Application.Models
{
    public class MapDefinition
    {
        public string ImageUrl { get; set; } = string.Empty;
        public int Width { get; set; }
        public int Height { get; set; }
        public MapPoint[] Points { get; set; } = Array.Empty<MapPoint>();
    }
}
