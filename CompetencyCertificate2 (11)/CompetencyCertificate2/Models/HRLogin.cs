using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace CompetencyCertificate.Models
{
    public class HRLogin
    {
        [Key]
        [Column(TypeName = "NVARCHAR(60)")]
        public string? employee_id { get; set; }

        [Column(TypeName ="NVARCHAR(60)")]
        public string? Password { get; set; } = "";
        [Column(TypeName = "NVARCHAR(60)")]
        [SwaggerIgnore]
        public string Designation { get; set; } = "HR";
    }
}
