using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Danplanner.Application.Interfaces.BruteForceDetectionInterfaces
{
    public interface IBruteForceDetection
    {
        bool IsLockedOut(string username);
        void RecordFailedAttempt(string username);
        void RecordSuccessfulLogin(string username);
    }
}