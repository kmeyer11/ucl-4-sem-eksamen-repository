using Danplanner.Application.Interfaces.AccommodationInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;
using Microsoft.AspNetCore.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Persistence.DbMangagerDir;
using Microsoft.EntityFrameworkCore;

namespace Danplanner.Persistence.Repositories.AccommodationRepositories
{
    public class AccommodationRepositoryGet : IAccommodationGetAll, IAccommodationGetAllFromTxt, IAccommodationGetById, IAccommodationGetById2
    {
        private readonly string _dataFilePath;
        private readonly DbManager _db;

        public AccommodationRepositoryGet(IWebHostEnvironment env, DbManager dbManger)
        {
            _dataFilePath = Path.Combine(env.WebRootPath ?? string.Empty, "data", "accommodations.txt");
            _db = dbManger;
        }

        public async Task<List<Accommodation>> GetAllAccommodationsAsync()
        {
            return await _db.Accommodation.ToListAsync();
        }

        public async Task<IReadOnlyList<Accommodation>> GetAccommodationsFromTxtAsync()
        {
            if (!File.Exists(_dataFilePath))
                throw new FileNotFoundException("Accommodation data file not found", _dataFilePath);

            var lines = await File.ReadAllLinesAsync(_dataFilePath);
            var result = new List<Accommodation>();

            foreach (var raw in lines)
            {
                var line = raw?.Trim();
                if (string.IsNullOrEmpty(line)) continue;
                if (line.StartsWith("#")) continue;

                var parts = line.Split('|');
                if (parts.Length < 4) continue;

                var entity = new Accommodation
                {
                    // 0: navn, 1: beskrivelse, 2: pris, 3: billede
                    AccommodationName = parts[0].Trim(),
                    AccommodationDescription = parts[1].Trim(),
                    PricePerNight = decimal.TryParse(parts[2].Trim(), out var price) ? price : null,
                    ImageUrl = parts[3].Trim(),
                };

                var nameLower = entity.AccommodationName.ToLowerInvariant();
                if (nameLower.Contains("luksus"))
                    entity.Category = "luksushytte";
                else if (nameLower.Contains("hytte"))
                    entity.Category = "hytte";
                else if (nameLower.Contains("plads"))
                    entity.Category = "plads";

                result.Add(entity);
            }

            return result;
        }

        public async Task<IReadOnlyCollection<int>> GetAvailableIdsAsync(DateTime? start,DateTime? end)
        {
            // Start med alle accommodations
            var query = _db.Accommodation.AsQueryable();

            // Hvis der ikke er valgt datoer, returnér alle
            if (!start.HasValue || !end.HasValue)
            {
                return await query
                    .Select(a => a.AccommodationId)
                    .ToListAsync();
            }

            var s = start.Value.Date;
            var e = end.Value.Date;

            // Find accommodationId'er med overlappende booking i perioden
            var bookedIds = await _db.Booking
                .Where(b => b.CheckInDate < e && b.CheckOutDate > s)
                .Select(b => b.AccommodationId)
                .Distinct()
                .ToListAsync();

            // Fjerner dem der er booket i perioden
            if (bookedIds.Count > 0)
            {
                query = query.Where(a => !bookedIds.Contains(a.AccommodationId));
            }

            return await query
                .Select(a => a.AccommodationId)
                .ToListAsync();
        }

        public async Task<AccommodationDto> AccommodationGetByIdAsync(int id)
        {
            Accommodation accommodation = await _db.Accommodation.FirstOrDefaultAsync(a => a.AccommodationId == id);

            return new AccommodationDto()
            {
                AccommodationId = accommodation.AccommodationId,
                AccommodationName = accommodation.AccommodationName,
                AccommodationDescription = accommodation.AccommodationDescription,
                PricePerNight = accommodation?.PricePerNight,
                Availability = accommodation.Availability,
                ImageUrl = accommodation?.ImageUrl,
                Category = accommodation?.Category,
            };
        }
    }
}
