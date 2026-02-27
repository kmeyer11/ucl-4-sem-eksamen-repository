using Danplanner.Application.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Services
{
    public static class ContactInfoReader
    {
        public static ContactInformation Load(string path)
        {
            var info = new ContactInformation();

            foreach (var line in File.ReadAllLines(path))
            {
                if (!line.Contains("=")) continue;

                var parts = line.Split('=', 2);
                var key = parts[0].Trim();
                var value = parts[1].Trim();

                switch (key)
                {
                    case "ContactPhoneNumber": info.ContactPhoneNumber = value; break;
                    case "ContactEmail": info.ContactEmail = value; break;
                    case "ContactAdress": info.ContactAdress = value; break;
                }
            }

            return info;
        }
    }    
}

