using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models
{
    public class ContactInformation
    {
        public int ContactInformationId { get; set; }
        public string ContactPhoneNumber { get; set; }
        public string ContactEmail { get; set; }
        public string ContactAdress { get; set; }
    }
}
