using AuthJwtAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthJwtAPI.Data
{
    public class MyDbContext : DbContext
    {
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
    }
}
