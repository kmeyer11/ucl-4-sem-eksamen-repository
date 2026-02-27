using Danplanner.Application.Interfaces.OrderlineInterfaces;
using Danplanner.Domain.Entities;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Danplanner.Persistence.Repositories.OrderlineRepositories
{
    public class OrderlineRepositoryPost : IOrderlineAdd
    {
        private readonly DbManager _dbManager;

        public OrderlineRepositoryPost(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<int> OrderlineAddAsync(int bookingId)
        {
            var orderline = new Orderline
            {
                BookingId = bookingId,
            };

            await _dbManager.Orderline.AddAsync(orderline);
            await _dbManager.SaveChangesAsync();

            return orderline.OrderlineId;
        }
    }
}
