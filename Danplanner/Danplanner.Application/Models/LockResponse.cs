using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Application.Models
{
    public sealed class LockResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; } = "";
        public DateTime ExpiresAt { get; set; }
        public string Message { get; set; } = "";
    }
}
