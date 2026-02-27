using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.ConfirmationInterfaces
{
    public interface IParseDate
    {
        DateTime? ParseDate(string? raw, out string display);
    }

}
