using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    public class SubDepartment
    {
        [Key]
        [Column(TypeName = "nvarchar(60)")]
        public string SubDepartmentName { get; set; } = "";

        [Column(TypeName = "nvarchar(60)")]
        [ForeignKey("Department")]
        public string? DepartmentName { get; set; }
        [JsonIgnore]
        public Department? Department { get; set; }

        [JsonIgnore]
        public List<Employee> Employees { get; set; } = new List<Employee>();


    }
}
