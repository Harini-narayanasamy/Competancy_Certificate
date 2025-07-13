using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    public class Generated
    {
        [Key]
        [Column(TypeName = "nvarchar(60)")]
        [ForeignKey("Employee")]
        public string EmployeeId { get; set; } = "";
        [JsonIgnore]
        
        public Employee? Employee { get; set; }
        [Column(TypeName = "varbinary(max)")]
        [Required]
        public byte[] CompetencyCertificate { get; set; } = Array.Empty<byte>();
        [Column(TypeName = "nvarchar(60)")]
        public string? Validity { get; set; } = null;
    }
}
