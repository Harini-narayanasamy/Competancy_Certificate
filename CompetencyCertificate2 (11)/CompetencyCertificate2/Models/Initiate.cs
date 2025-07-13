using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    public class Initiate
    {
        [Key]
        [Column(TypeName = "nvarchar(60)")]
        
        public string employee_id { get; set; } = "";
        [JsonIgnore]
        [ForeignKey("employee_id")]
        public Employee? Employee { get; set; }
    }
}
