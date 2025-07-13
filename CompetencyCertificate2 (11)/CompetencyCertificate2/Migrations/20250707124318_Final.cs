using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CompetencyCertificate.Migrations
{
    /// <inheritdoc />
    public partial class Final : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Contractor",
                columns: table => new
                {
                    ContractorName = table.Column<string>(type: "NVARCHAR(60)", nullable: false),
                    Logo = table.Column<byte[]>(type: "varbinary(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Contractor", x => x.ContractorName);
                });

            migrationBuilder.CreateTable(
                name: "Department",
                columns: table => new
                {
                    DepartmentName = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    DepartmentCode = table.Column<string>(type: "nvarchar(60)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Department", x => x.DepartmentName);
                });

            migrationBuilder.CreateTable(
                name: "Designation",
                columns: table => new
                {
                    Designation_Name = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    designation_type = table.Column<int>(type: "int", nullable: false),
                    DesignationCode = table.Column<string>(type: "nvarchar(60)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Designation", x => x.Designation_Name);
                });

            migrationBuilder.CreateTable(
                name: "HRLogin",
                columns: table => new
                {
                    employee_id = table.Column<string>(type: "NVARCHAR(60)", nullable: false),
                    Password = table.Column<string>(type: "NVARCHAR(60)", nullable: true),
                    Designation = table.Column<string>(type: "NVARCHAR(60)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HRLogin", x => x.employee_id);
                });

            migrationBuilder.CreateTable(
                name: "SubDeparment",
                columns: table => new
                {
                    SubDepartmentName = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    DepartmentName = table.Column<string>(type: "nvarchar(60)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SubDeparment", x => x.SubDepartmentName);
                    table.ForeignKey(
                        name: "FK_SubDeparment_Department_DepartmentName",
                        column: x => x.DepartmentName,
                        principalTable: "Department",
                        principalColumn: "DepartmentName");
                });

            migrationBuilder.CreateTable(
                name: "Employee",
                columns: table => new
                {
                    Employee_id = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    Employee_name = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    PhotoBase64 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Photo = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    Employee_type = table.Column<int>(type: "int", nullable: false),
                    CategoryName = table.Column<int>(type: "int", nullable: false),
                    ContractorName = table.Column<string>(type: "NVARCHAR(60)", nullable: true),
                    DOB = table.Column<DateTime>(type: "date", nullable: false),
                    EPF_UAN_NO = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    ESA_NO = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    BankName = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    BankAccountNumber = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    Passbook = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    PassbookBase64 = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    JoiningDate = table.Column<DateTime>(type: "date", nullable: false),
                    Designation_Name = table.Column<string>(type: "nvarchar(60)", nullable: true),
                    DepartmentName = table.Column<string>(type: "nvarchar(60)", nullable: true),
                    SubDepartmentName = table.Column<string>(type: "nvarchar(60)", nullable: true),
                    AadharNo = table.Column<int>(type: "int", nullable: false),
                    BloodGroup = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    ContactNo = table.Column<string>(type: "nvarchar(60)", nullable: true),
                    EmerContactNo = table.Column<string>(type: "nvarchar(60)", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Employee", x => x.Employee_id);
                    table.ForeignKey(
                        name: "FK_Employee_Contractor_ContractorName",
                        column: x => x.ContractorName,
                        principalTable: "Contractor",
                        principalColumn: "ContractorName");
                    table.ForeignKey(
                        name: "FK_Employee_Department_DepartmentName",
                        column: x => x.DepartmentName,
                        principalTable: "Department",
                        principalColumn: "DepartmentName");
                    table.ForeignKey(
                        name: "FK_Employee_Designation_Designation_Name",
                        column: x => x.Designation_Name,
                        principalTable: "Designation",
                        principalColumn: "Designation_Name");
                    table.ForeignKey(
                        name: "FK_Employee_SubDeparment_SubDepartmentName",
                        column: x => x.SubDepartmentName,
                        principalTable: "SubDeparment",
                        principalColumn: "SubDepartmentName");
                });

            migrationBuilder.CreateTable(
                name: "EmployeeLogin",
                columns: table => new
                {
                    employee_id = table.Column<string>(type: "NVARCHAR(60)", nullable: false),
                    Password = table.Column<string>(type: "NVARCHAR(60)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmployeeLogin", x => x.employee_id);
                    table.ForeignKey(
                        name: "FK_EmployeeLogin_Employee_employee_id",
                        column: x => x.employee_id,
                        principalTable: "Employee",
                        principalColumn: "Employee_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Generated",
                columns: table => new
                {
                    EmployeeId = table.Column<string>(type: "nvarchar(60)", nullable: false),
                    CompetencyCertificate = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    Validity = table.Column<string>(type: "nvarchar(60)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Generated", x => x.EmployeeId);
                    table.ForeignKey(
                        name: "FK_Generated_Employee_EmployeeId",
                        column: x => x.EmployeeId,
                        principalTable: "Employee",
                        principalColumn: "Employee_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Initiate",
                columns: table => new
                {
                    employee_id = table.Column<string>(type: "nvarchar(60)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Initiate", x => x.employee_id);
                    table.ForeignKey(
                        name: "FK_Initiate_Employee_employee_id",
                        column: x => x.employee_id,
                        principalTable: "Employee",
                        principalColumn: "Employee_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Employee_ContractorName",
                table: "Employee",
                column: "ContractorName");

            migrationBuilder.CreateIndex(
                name: "IX_Employee_DepartmentName",
                table: "Employee",
                column: "DepartmentName");

            migrationBuilder.CreateIndex(
                name: "IX_Employee_Designation_Name",
                table: "Employee",
                column: "Designation_Name");

            migrationBuilder.CreateIndex(
                name: "IX_Employee_SubDepartmentName",
                table: "Employee",
                column: "SubDepartmentName");

            migrationBuilder.CreateIndex(
                name: "IX_SubDeparment_DepartmentName",
                table: "SubDeparment",
                column: "DepartmentName");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EmployeeLogin");

            migrationBuilder.DropTable(
                name: "Generated");

            migrationBuilder.DropTable(
                name: "HRLogin");

            migrationBuilder.DropTable(
                name: "Initiate");

            migrationBuilder.DropTable(
                name: "Employee");

            migrationBuilder.DropTable(
                name: "Contractor");

            migrationBuilder.DropTable(
                name: "Designation");

            migrationBuilder.DropTable(
                name: "SubDeparment");

            migrationBuilder.DropTable(
                name: "Department");
        }
    }
}
