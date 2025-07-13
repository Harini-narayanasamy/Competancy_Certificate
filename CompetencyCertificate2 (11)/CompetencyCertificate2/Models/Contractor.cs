using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace CompetencyCertificate.Models
{
    public class Contractor
    {
        [Key]
        [Column(TypeName = "NVARCHAR(60)")]
        public string ContractorName { get; set; } = null!;

        [Required]
        public byte[] Logo { get; set; } = Array.Empty<byte>();

        [JsonIgnore]
        public List<Employee> Employees { get; set; } = new List<Employee>();
    }

}
