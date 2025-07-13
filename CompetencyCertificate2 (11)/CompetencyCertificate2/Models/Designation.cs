using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    // Designation.cs

    public class Designation
    {

        [Key]
        [Column(TypeName = "nvarchar(60)")]
        public string Designation_Name { get; set; } = "";
        [Required]
        public EmployeeType designation_type { get; set; }

        [Column(TypeName = "nvarchar(60)")]
        public string DesignationCode { get; set; } = "";
        [JsonIgnore]
        public List<Employee> Employees { get; set; } = new List<Employee>();


    }

}
