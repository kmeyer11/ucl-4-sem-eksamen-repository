using Danplanner.Domain.Entities;
using Danplanner.Application.Models.ModelsDto;
using Danplanner.Persistence.DbMangagerDir;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Danplanner.Application.Interfaces.OrderlineInterfaces;

namespace Danplanner.Persistence.Repositories.OrderlineRepositories
{
    public class OrderlineRepositoryGet : IOrderlineGetById
    {
        private readonly DbManager _dbManager;

        public OrderlineRepositoryGet(DbManager dbManager)
        {
            _dbManager = dbManager;
        }

        public async Task<OrderlineDto> OrderlineGetByIdAsync(int id)
        {
            var orderline = await _dbManager.Orderline.FirstOrDefaultAsync(a => a.OrderlineId == id);

            return new OrderlineDto
            {
                TotalPrice = orderline.TotalPrice,
                BookingId = orderline.BookingId,
            };
        }
    }
}
