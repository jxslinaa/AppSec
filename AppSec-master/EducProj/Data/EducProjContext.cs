using System;
using AppSec.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using AppSec.Models;

namespace AppSec.Models
{
    public partial class AppSecContext : DbContext
    {
        public AppSecContext()
        {
        }

        public AppSecContext(DbContextOptions<AppSecContext> options)
            : base(options)
        {

        }
        //this function used for bulk operation
        //to implement this function in your destination 
        public int executeSql(string sql)
        {
            return base.Database.ExecuteSqlCommand(sql);
        }
        public static string connString { get; set; }

        public virtual DbSet<Users> Users { get; set; }
        public virtual DbSet<PasswordHistory> PasswordHistory { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer(connString);
            }
            //optionsBuilder.UseSqlServer("Data Source=DESKTOP-95EL5EC\\SQLEXPRESS;Initial Catalog=CanERP;integrated security=True;MultipleActiveResultSets=True;Database=CanERP;Trusted_Connection=True;");
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Users>(entity =>
            {
                entity.ToTable("Users");
                entity.Property(e => e.UserId).HasColumnName("UserId");
            });
        }
    }
}
          

        

