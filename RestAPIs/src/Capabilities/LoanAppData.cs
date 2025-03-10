
//################################################################################################################################
//# Author(s): Dr. Gail Zhou & GitHub CoPiLot
//# Last Updated: March 2025
//################################################################################################################################

namespace RestAPIs.Capabilities
{
    public class LoanAppData
    {
        public string FirstName { get; set; } = string.Empty;
        public string MiddleName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string SSN { get; set; } = string.Empty; //  Social Security Number
        public DateOnly DoB { get; set; } = new DateOnly(1990, 01, 01); // Date of Birth
        public decimal CurrentCashAsset { get; set; } = 100000.0M;
        public decimal AnnualIncome { get; set; } = 100000.0M;
        public bool IsMarried { get; set; } = false;
        public string Gender { get; set; } = string.Empty;
        public string Employer { get; set; } = string.Empty;
        public decimal YearsEmployedByCurrentEmployer { get; set; } = 5.0M;
        public string PhoneNumber { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public decimal PurchasePrice { get; set; } = 500000.0M;
        public decimal DownPayment { get; set; } = 100000.0M;
        public decimal LoanCost { get; set; } = 100000.0M;
        public int LoanTermInYears { get; set; } = 30;
        public decimal InterestRate { get; set; } = 7.0M;
    }
}


