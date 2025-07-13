using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    public class EmployeeLogin
    {
        [Key]
        [Column(TypeName = "NVARCHAR(60)")]
        [ForeignKey("Employee")]
        public string? employee_id { get; set; }

        [JsonIgnore]
        
        public Employee? Employee { get; set; }
        [Column(TypeName = "NVARCHAR(60)")]
        [Required]
        public string? Password { get; set; }

    }
}
