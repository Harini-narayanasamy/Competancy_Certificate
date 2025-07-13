using CompetencyCertificate.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CompetencyCertificate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public UserController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public class LoginDto
        {
            public string EmployeeId { get; set; } = "";
            public string Password { get; set; } = "";
            
        }
        [HttpPost("Login")]
        public IActionResult Login([FromBody] LoginDto loginDto)
        {
            try
            {
                if (string.IsNullOrEmpty(loginDto.EmployeeId) || string.IsNullOrEmpty(loginDto.Password))
                {
                    return BadRequest("Employee ID and Password are required.");
                }

                // Try executive login
                var login = _context.EmployeeLogin.FirstOrDefault(e => e.employee_id == loginDto.EmployeeId && e.Password == loginDto.Password);
                if (login != null)
                {
                    var employeeDetails = _context.Employee.FirstOrDefault(e => e.Employee_id == loginDto.EmployeeId);
                    if (employeeDetails == null)
                        return Unauthorized("Employee details not found.");
                    var token = GenerateJwtToken(employeeDetails.Employee_id.ToString());
                    return Ok(new
                    {
                        token,
                        message = "Executive Login successful",
                        employeeDetails
                    });
                }

                // Try HR login
                var hrLogin = _context.HRLogin.FirstOrDefault(e => e.employee_id == loginDto.EmployeeId && e.Password == loginDto.Password);
                if (hrLogin != null)
                {
                    var employeeDetails = hrLogin; // reuse name for consistency
                    if (employeeDetails == null)
                        return Unauthorized("Employee details not found.");
                    var token = GenerateJwtToken(employeeDetails.employee_id.ToString());
                    return Ok(new
                    {
                        token,
                        message = "HR Login successful",
                        employeeDetails
                    });
                }

                return Unauthorized("Invalid Employee ID or Password.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Login Error: " + ex.Message);
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        // Helper method for token generation
        private string GenerateJwtToken(string userId)
        {
            var jwtSecret = _configuration["AppSettings:JWTSecret"];
            var signInKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.NameIdentifier, userId)
        }),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(signInKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }



        [HttpPost("AddEmployee")]
        public IActionResult AddEmployee(Employee obj)
        {
            if (!string.IsNullOrWhiteSpace(obj.PhotoBase64)) // Fix: Check PhotoBase64 instead of Photo
            {
                try
                {
                    obj.Photo = Convert.FromBase64String(obj.PhotoBase64); // Fix: Assign decoded byte array to Photo
                }
                catch (FormatException)
                {
                    return BadRequest(new { message = "Invalid base64 string for Photo." });
                }
                if (!string.IsNullOrWhiteSpace(obj.PassbookBase64))
                {
                    try
                    {
                        obj.Passbook = Convert.FromBase64String(obj.PassbookBase64);
                    }
                    catch
                    {
                        return BadRequest(new { message = "Invalid base64 string for Passbook." });
                    }
                }
                _context.Employee.Add(obj);
                _context.SaveChanges();
                return Ok(new { message = "Employee added successfully" });
            }


            return BadRequest(new { message = "Photo is required." });
        }

        [HttpPost("AddEmployeeLogin")]
        public IActionResult AddEmployeeLogin(EmployeeLogin obj)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            _context.EmployeeLogin.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "Employee login added successfully" });
        }
        [HttpPost("AddContractor")]
        public IActionResult AddContractor(Contractor obj)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            _context.Contractor.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "Contractor added successfully" });
        }
        [HttpPost("AddHRogin")]
        public IActionResult AddHRLogin(HRLogin obj)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            _context.HRLogin.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "HR login added successfully" });
        }
        [HttpPost("AddDepartment")]
        public IActionResult AddDepartment(Department obj)
        {
            _context.Department.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "Department added successfully" });
        }
        [HttpPost("AddSubDepartment")]
        public IActionResult AddSubDeparment(SubDepartment obj) { 
            _context.SubDeparment.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "SubDepartment added successfully" });
        }
        [HttpPost("AddDesignation")]
        public IActionResult AddDesignation([FromBody] Designation obj)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            _context.Designation.Add(obj);
            _context.SaveChanges();
            return Ok(new { message = "Designation added successfully" });
        }
        [HttpGet("GetAllContractors")]
        public IActionResult GetAllContractors()
        {
            var contractors = _context.Contractor.ToList();
            if (contractors == null || !contractors.Any())
            {
                return NotFound(new { message = "No contractors found" });
            }
            return Ok(contractors);
        }
        [HttpGet("GetCountEmployees")]
        public IActionResult GetCountEmployees()
        {
            var count = _context.Employee.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountDepartments")]
        public IActionResult GetCountDepartments()
        {
            var count = _context.Department.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountDesignations")]
        public IActionResult GetCountDesignations()
        {
            var count = _context.Designation.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountContractors")]
        public IActionResult GetCountContractors()
        {
            var count = _context.Contractor.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountSubDepartments")]
        public IActionResult GetCountSubDepartments()
        {
            var count = _context.SubDeparment.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountEmployeesByDepartmentId/{departmentId}")]
        public IActionResult GetCountEmployeesByDepartmentId(string departmentId)
        {
            if (string.IsNullOrWhiteSpace(departmentId))
                return BadRequest("Department ID is required.");

            try
            {
                var normalized = departmentId.Trim().ToLower();
                var count = _context.Employee.Count(e =>
                    e.DepartmentName != null &&
                    e.DepartmentName.Trim().ToLower() == normalized
                );

                return Ok(new { count });
            }
            catch (Exception ex)
            {
                // Log the error (to console/file/etc)
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpGet("GetCountEmployeesBySubDepartmentId/{subDepartmentId}")]
        public IActionResult GetCountEmployeesBySubDepartmentId(string subDepartmentId)
        {
            var count = _context.Employee.Count(e => e.SubDepartmentName == subDepartmentId);
            return Ok(new { count });
        }
        [HttpGet("GetCountGenerated")]
        public IActionResult GetCountGenerated()
        {
            var count = _context.Generated.Count();
            return Ok(new { count });
        }
        [HttpGet("GetCountGeneratedByDepartment/{DepartmentName}")]
        public IActionResult GetCountGeneratedByDepartment(string DepartmentName)
        {
            var count = _context.Generated
                .Include(g => g.Employee)
                .Where(g => g.Employee != null && g.Employee.DepartmentName == DepartmentName)
                .Count();

            return Ok(new { count });
        }
        [HttpGet("GetCountGeneratedBySubDepartment/{SubDepartmentName}")]
        public IActionResult GetCountGeneratedBySubDepartment(string SubDepartmentName)
        {
            var count = _context.Generated.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.SubDepartmentName == SubDepartmentName).Count();
            return Ok(new { count });
        }
        [HttpGet("GetGenerated)")]
        public IActionResult GetGenerated()
        {
            var generated = _context.Generated.ToList();
            if (generated == null || !generated.Any())
            {
                return NotFound(new { message = "No generated records found" });
            }
            return Ok(generated);
        }
        [HttpGet("GetDesignationByType/{type}")]
        public IActionResult GetDesignationByType(string type)
        {
            if (!Enum.TryParse<EmployeeType>(type, true, out var parsedType))
            {
                return BadRequest("Invalid designation type.");
            }

            var designation = _context.Designation
                .Where(g => g.designation_type == parsedType)
                .ToList();

            return Ok(designation);
        }
        [HttpGet("GetSubDepartmentByName/{subdept}")]
        public IActionResult GetSubDepartmentByName(string subdept)
        {
            var sub = _context.SubDeparment.Find(subdept);
            if (sub == null)
            {
                NotFound(new { message = "Subdepartment Not Found " });
            }
            return Ok(sub);
        }
        [HttpGet("GetGenratedByDepartment/{DepartmentName}")]
        public IActionResult GetCount(string DepartmentName) {
            var generated = _context.Generated.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.DepartmentName == DepartmentName).ToList();
            if (generated == null || !generated.Any())
            {
                return NotFound(new { message = "No generated records found for this department" });
            }
            return Ok(generated);
        }

        [HttpGet("GetGenratedBySubDepartment/{SubDepartmentName}")]
        public IActionResult GetGenratedBySubDepartment(string SubDepartmentName)
        {
            var generated = _context.Generated.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.SubDepartmentName == SubDepartmentName).ToList();
            if (generated == null || !generated.Any())
            {
                return NotFound(new { message = "No generated records found for this sub-department" });
            }
            return Ok(generated);
        }
        [HttpGet("GetSbDepartmentsByDepartmentId/{departmentId}")]
        public IActionResult GetSbDepartmentsByDepartmentId(string departmentId)
        {
            var subDepartments = _context.SubDeparment.Where(sd => sd.DepartmentName == departmentId).ToList();
            if (subDepartments == null || !subDepartments.Any())
            {
                return NotFound(new { message = "No sub-departments found for this department" });
            }
            return Ok(subDepartments);
        }
        
        [HttpGet("GetEmployeesBySubDepartmentId/{subDepartmentId}")]
        public IActionResult GetEmployeesBySubDepartmentId(string subDepartmentId)
        {
            var employees = _context.Employee.Where(e => e.SubDepartmentName == subDepartmentId).ToList();
            if (employees == null || !employees.Any())
            {
                return NotFound(new { message = "No employees found for this sub-department" });
            }
            return Ok(employees);
        }
        [HttpGet("GetDesignationByDesignationName/{designation}")]
        public IActionResult GetDesignationByName(string designation)
        {
            var desig = _context.Designation.Find(designation);
            if(desig == null)
            {
                return NotFound(new { message = "No desigantion found" });
            }
            return Ok(desig);
        }
        [HttpGet("GetEmployeesByDepartmentId/{departmentId}")]
        public IActionResult GetEmployeesByDepartmentId(string departmentId)
        {
            var employees = _context.Employee.Where(e => e.DepartmentName == departmentId).ToList();
            if (employees == null || !employees.Any())
            {
                return NotFound(new { message = "No employees found for this department" });
            }
            return Ok(employees);
        }
        [HttpGet("GetContractorByName/{contractorName}")]
        public IActionResult GetContractorByName(string contractorName)
        {
            var contractor = _context.Contractor.Find(contractorName);
            if(contractor == null)
            {
                return NotFound(new { message = "No Contractor Found" });
            }
            return Ok(contractor);
        }
        [HttpGet("GetDeoartmentById/{id}")]
        public IActionResult GetDepartmentById(string id)
        {
            var department = _context.Department.Find(id);
            if(department != null)
            {
                return Ok(department);
            }
            return NotFound(new { message = "No department Found" });
        }

        [HttpGet("GetAllEmployees")]
        public IActionResult GetAllEmployees()
        {
            var employees = _context.Employee.ToList();
            if (employees == null || !employees.Any())
            {
                return NotFound(new { message = "No employees found" });
            }
            return Ok(employees);
        }
        [HttpGet("GetAllGenerated")]
        public IActionResult GetAllGenerated()
        {
            var generated = _context.Generated.ToList();
            if (generated == null)
            {
                return NotFound(new { message = "No Generated" });
            }
            return Ok(generated);
        }
        [HttpGet("GetAllInitiateBySubdepartment/{SubDepartmentName}")]
        public IActionResult GetAllInitiateBySubdepartment(string SubDepartmentName)
        {
            var Data = _context.Initiate.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.SubDepartmentName == SubDepartmentName);
            return Ok(new { Data });

        }
        public class GeneratedDto
        {
            public string EmployeeId { get; set; } = "";
            public string EmployeeName { get; set; } = "";
            public string CompetencyCertificate { get; set; } = ""; // Base64 string
            public string? Validity { get; set; } = null;
        }
        [HttpPost("AddGenerated")]
        public IActionResult AddGenerated([FromBody] GeneratedDto obj)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                // Convert base64 string to byte array
                byte[] certificateBytes = Convert.FromBase64String(obj.CompetencyCertificate);

                var generated = new Generated
                {
                    EmployeeId = obj.EmployeeId,  // This matches your Generated model property
                    CompetencyCertificate = certificateBytes,
                    Validity = obj.Validity
                };

                _context.Generated.Add(generated);
                _context.SaveChanges();

                return Ok(new { message = "Generated added successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Error storing certificate", error = ex.Message });
            }
        }
        public class AddInitiateDto
        {
            [Column(TypeName = "nvarchar(60)")]
            public string employee_id { get; set; } = "";
        }
        [HttpPost("AddInitiate")]
        public async Task<IActionResult> AddInitiate(AddInitiateDto dto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Check if employee is already initiated
            var existingInitiate = await _context.Initiate
                .FirstOrDefaultAsync(i => i.employee_id == dto.employee_id);

            if (existingInitiate != null)
            {
                return BadRequest(new { message = "Employee is already initiated" });
            }

            var initiate = new Initiate
            {
                employee_id = dto.employee_id
            };

            _context.Initiate.Add(initiate);
            await _context.SaveChangesAsync();
            return Ok(new { message = "Initiate added successfully" });
        }
        [HttpGet("GetAllGeneratedById/{Id}")]
        public IActionResult GetAllGeneratedById(string Id)
        {
            var generatedData = _context.Generated
                .Include(g => g.Employee)
                .Where(g => g.EmployeeId == Id)
                .Select(g => new
                {
                    g.Employee.Employee_id,
                    g.Employee.Employee_name,
                    g.CompetencyCertificate
                })
                .ToList();

            if (!generatedData.Any())
            {
                return NotFound(new { message = "No generated data found for this employee." });
            }

            return Ok(generatedData);
        }

        [HttpGet("GetAllGeneratedByDepartment/{DepartmentName}")]
        public IActionResult GetAllGeneratedByDepartment(string DepartmentName)
        {
            var Data = _context.Generated.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.DepartmentName == DepartmentName);
            return Ok(new { Data });

        }

        [HttpGet("GetAllGeneratedBySubDepartment/{SubDepartmentName}")]
        public IActionResult GetAllGeneratedBySubdepartment(string SubDepartmentName)
        {
            var Data = _context.Generated.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.SubDepartmentName == SubDepartmentName);
            return Ok(new { Data });

        }
        [HttpGet("GetAllInitializedBySubDepartment/{SubDepartmentName}")]
        public IActionResult GetAllInitializedBySubdepartment(string SubDepartmentName)
        {
            var Data = _context.Initiate.Include(g => g.Employee).Where(g => g.Employee != null && g.Employee.SubDepartmentName == SubDepartmentName);
            return Ok(new { Data });

        }
        [HttpGet("GetAllDepartments")]
        public IActionResult GetAllDepartments()
        {
            var departments = _context.Department.ToList();
            if (departments == null || !departments.Any())
            {
                return NotFound(new { message = "No departments found" });
            }
            return Ok(departments);
        }
        [HttpGet("GetAllDesignations")]
        public IActionResult GetAllDesignations()
        {
            var designations = _context.Designation.ToList();
            if (designations == null || !designations.Any())
            {
                return NotFound(new { message = "No designations found" });
            }
            return Ok(designations);
        }
        [HttpGet("GetEmployeeById/{id}")]
        public IActionResult GetEmployeeById(string id)
        {
            var employee = _context.Employee.FirstOrDefault(e => e.Employee_id == id);
            if (employee == null)
            {
                return NotFound(new { message = "Employee not found" });
            }
            return Ok(employee);
        }

[HttpPut("UpdateEmployee/{id}")]
public IActionResult UpdateEmployee(string id, [FromBody] Employee updatedEmployee)
{
    var existingEmployee = _context.Employee.FirstOrDefault(e => e.Employee_id == id);
    if (existingEmployee == null)
    {
        return NotFound("Employee not found.");
    }

    // Apply updates only to scalar values (not navigation properties directly)
    _context.Entry(existingEmployee).CurrentValues.SetValues(updatedEmployee);

            // Optional: manually handle navigation properties if needed
            existingEmployee.Employee_name = updatedEmployee.Employee_name;
            existingEmployee.PhotoBase64 = updatedEmployee.PhotoBase64;
            existingEmployee.ContractorName = updatedEmployee.ContractorName;
            existingEmployee.Employee_type = updatedEmployee.Employee_type;
            existingEmployee.CategoryName = updatedEmployee.CategoryName;
            existingEmployee.DepartmentName = updatedEmployee.DepartmentName;
            existingEmployee.SubDepartmentName = updatedEmployee.SubDepartmentName;
            existingEmployee.Designation_Name = updatedEmployee.Designation_Name;
            existingEmployee.DOB = updatedEmployee.DOB;
            existingEmployee.EPF_UAN_NO = updatedEmployee.EPF_UAN_NO;
            existingEmployee.ESA_NO = updatedEmployee.ESA_NO;
            existingEmployee.BankName = updatedEmployee.BankName;
            existingEmployee.BankAccountNumber = updatedEmployee.BankAccountNumber;
            existingEmployee.PassbookBase64 = updatedEmployee.PassbookBase64;
            existingEmployee.JoiningDate = updatedEmployee.JoiningDate;
            existingEmployee.AadharNo = updatedEmployee.AadharNo;
            existingEmployee.BloodGroup = updatedEmployee.BloodGroup;
            existingEmployee.ContactNo = updatedEmployee.ContactNo;
            existingEmployee.EmerContactNo = updatedEmployee.EmerContactNo;
            existingEmployee.Status = updatedEmployee.Status;

            _context.SaveChanges();

    return Ok(new { message = "Employee updated successfully" });
}

        [HttpDelete("EmployeeLoginDelete/{id}")]
        public IActionResult DeleteEmployeeLogin(string id)
        {
            var employee = _context.EmployeeLogin.Find(id);
            if(employee == null)
            {
                return NotFound(new { message = "Employee Not Foound" });
            }
            _context.EmployeeLogin.Remove(employee);
            _context.SaveChanges();
            return Ok(new { message = "Employee login deleted" });
        }

        [HttpDelete("DeleteEmployee/{id}")]
        public IActionResult DeleteEmployee(string id)
        {
            var employee = _context.Employee.Find(id);
            if (employee == null)
            {
                return NotFound(new { message = "Employee not found" });
            }
            _context.Employee.Remove(employee);
            _context.SaveChanges();
            return Ok(new { message = "Employee deleted successfully" });
        }
        [HttpPut("UpdateDepartment/{id}")]
        public IActionResult UpdateDepartment(string id, [FromBody] Department updatedDepartment)
        {
            var existingDepartment = _context.Department.Find(id);
            if (existingDepartment == null)
            {
                return NotFound("Department not found.");
            }
            existingDepartment.DepartmentName = updatedDepartment.DepartmentName;
            existingDepartment.DepartmentCode = updatedDepartment.DepartmentCode;

            _context.SaveChanges();

            return Ok(new { message = "Deapartment updated successfully" });
        }
        [HttpPut("UpdateSubDepartment/{subdept}")]
        public IActionResult UpdateSubDepartment(string subdept, [FromBody] SubDepartment updatedsubdept)
        {
            var existingsubdept = _context.SubDeparment.Find(subdept);
            if (existingsubdept == null)
            {
                return NotFound("SubDepartment not found");
            }
            existingsubdept.SubDepartmentName = updatedsubdept.SubDepartmentName;
            existingsubdept.DepartmentName = updatedsubdept.DepartmentName;
            _context.SaveChanges();
            return Ok(new { message = "Sub Department Updated Successfully" });
        }

        [HttpDelete("DeleteDepartment/{id}")]
        public IActionResult DeleteDepartment(string id)
        {
            var dept = _context.Department.Find(id);
            if (dept == null)
            {
                return NotFound(new { message = "Department Not Found" });

            }
            _context.Department.Remove(dept);
            _context.SaveChanges();
            return Ok(new { message = "Department Deleted Successfully" });

        }
        [HttpPut("UpdateDesignation/{id}")]
        public IActionResult UpdateDesignation(string id, [FromBody] Designation updatedDesignation)
        {
            var existingDesignation = _context.Designation.Find(id);
            if(existingDesignation == null)
            {
                return NotFound("Designation not found");
            }
            existingDesignation.Designation_Name = updatedDesignation.Designation_Name;
            existingDesignation.DesignationCode = updatedDesignation.DesignationCode;
            existingDesignation.designation_type = updatedDesignation.designation_type;
            _context.SaveChanges();
            return Ok(new { message = "Designation Updated" });
        }

        [HttpPut("EditContractor/{contractorname}")]
        public IActionResult EditContractor(string contractorname, [FromBody] Contractor updatedContractor) {
            var existingContractor = _context.Contractor.Find(contractorname);
            if(existingContractor == null)
            {
                return NotFound("Contractor not found");
            }
            existingContractor.ContractorName = updatedContractor.ContractorName;
            existingContractor.Logo = updatedContractor.Logo;
            _context.SaveChanges();
            return Ok(new { message = "Contractor Updated" });
        }
        [HttpDelete("DeleteDesignation/{id}")]
        public IActionResult DeleteDesignation(string id)
        {
            var existingDesignation = _context.Designation.Find(id);
            if(existingDesignation == null)
            {
                return NotFound(new { message = "Designation not found" });
            }
            _context.Designation.Remove(existingDesignation);
            _context.SaveChanges();
            return Ok(new { message = "Designation Deleted" });
        }
        [HttpDelete("DeleteInitiate")]
        public IActionResult DeleteInitiate(int id)
        {
            var initiate = _context.Initiate.Find(id);
            if (initiate == null)
            {
                return NotFound(new { message = "Initiate not found" });
            }
            _context.Initiate.Remove(initiate);
            _context.SaveChanges();
            return Ok(new { message = "Initiate deleted successfully" });
        }
        [HttpDelete("DeleteFromInitiate/{employeeId}")]
        public IActionResult DeleteFromInitiate(string employeeId)
        {
            try
            {
                var initiateRecord = _context.Initiate.FirstOrDefault(i => i.employee_id == employeeId);
                if (initiateRecord == null)
                {
                    return NotFound(new { message = "Employee not found in initiate table" });
                }

                _context.Initiate.Remove(initiateRecord);
                _context.SaveChanges();

                return Ok(new { message = "Employee deleted from initiate table successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Error deleting from initiate table", error = ex.Message });
            }
        }
    }
}
