using Microsoft.EntityFrameworkCore;

namespace CompetencyCertificate.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions options) : base(options)
        {
        }
        public DbSet<Department> Department { get; set; }
        public DbSet<Designation> Designation { get; set; }
        public DbSet<Employee> Employee { get; set; }
        public DbSet<Contractor> Contractor { get; set; }
        public DbSet<EmployeeLogin> EmployeeLogin { get; set; }

        public DbSet<Generated> Generated { get; set; }
        public DbSet<HRLogin> HRLogin { get; set; }

        public DbSet<Initiate> Initiate { get; set; }

        public DbSet<SubDepartment> SubDeparment { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure Employee-Designation relationship
            modelBuilder.Entity<Employee>()
                .HasOne(e => e.Contractor)
                .WithMany()
                .HasForeignKey(e => e.ContractorName)
                .HasPrincipalKey(c => c.ContractorName) // Ensure the Contractor table has this column
                .IsRequired(false); // Allow nulls

            modelBuilder.Entity<Employee>()
    .HasOne(e => e.Contractor)
    .WithMany(c => c.Employees)
    .HasForeignKey(e => e.ContractorName)
    .HasPrincipalKey(c => c.ContractorName);

        }

    }
}
