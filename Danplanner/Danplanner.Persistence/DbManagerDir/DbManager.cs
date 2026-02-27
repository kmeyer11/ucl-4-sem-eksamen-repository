using Danplanner.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Danplanner.Persistence.DbMangagerDir
{
    public class DbManager : DbContext
    {
        public DbManager(DbContextOptions<DbManager> options) : base(options) { }

        public DbSet<Accommodation> Accommodation => Set<Accommodation>();
        public DbSet<Addon> Addon => Set<Addon>();
        public DbSet<Admin> Admin => Set<Admin>();
        public DbSet<Booking> Booking => Set<Booking>();
        public DbSet<User> User => Set<User>();
        public DbSet<Orderline> Orderline => Set<Orderline>();
        public DbSet<Season> Season => Set<Season>();
    }

}
