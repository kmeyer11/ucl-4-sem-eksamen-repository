using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Danplanner.Application.Interfaces.ConfirmationInterfaces;
using Danplanner.Application.Models.ModelsDto;

namespace Danplanner.Application.Services
{
    public class ParseDateService : IParseDate
    {
        public DateTime? ParseDate(string? raw, out string display)
        {
            display = "—";
            if (string.IsNullOrEmpty(raw))
                return null;

            if (DateTime.TryParseExact(
                    raw,
                    "yyyy-MM-dd",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.None,
                    out var dt))
            {
                display = dt.ToString("d. MMMM", CultureInfo.GetCultureInfo("da-DK"));
                return dt.Date;
            }

            display = raw;
            return null;
        }
    }
}
