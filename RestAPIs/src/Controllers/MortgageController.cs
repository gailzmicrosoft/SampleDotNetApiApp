//################################################################################################################################
//# Author(s): Dr. Gail Zhou & GitHub CoPiLot
//# Last Updated: March 2025
//################################################################################################################################

//using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RestAPIs.Controllers
{
    //[Authorize]
    [ApiController]
    [Route("[controller]")]
    public class MortgageController : ControllerBase
    {
        private readonly ILogger<MortgageController> _logger;

        public MortgageController(ILogger<MortgageController> logger)
        {
            _logger = logger;
        }

        [HttpGet("GetPreApprovalAmount")]
        public IActionResult GetPreApprovalAmount(decimal annualIncome, decimal annualLiability, int loanTermYears)
        {
            if (annualIncome <= 0 || annualLiability < 0 || (loanTermYears != 15 && loanTermYears != 30))
            {
                return BadRequest("Invalid input parameters.");
            }

            decimal frontEndRatio;
            decimal backEndRatio;
            decimal preApprovalAmount;

            if (loanTermYears == 30)
            {
                frontEndRatio = 0.28m;
                backEndRatio = 0.36m;
            }
            else // 15-year fixed mortgage
            {
                frontEndRatio = 0.25m;
                backEndRatio = 0.33m;
            }

            var monthlyIncome = annualIncome / 12; 
            var monthlyLiability = annualLiability / 12;

            var maxHousingExpense = monthlyIncome * frontEndRatio;
            var maxTotalDebt = (monthlyIncome * backEndRatio) - monthlyLiability;

            preApprovalAmount = Math.Min(maxHousingExpense, maxTotalDebt) * loanTermYears * 12;

            if (preApprovalAmount <= 0)
            {
                preApprovalAmount = 0; // No pre-approval amount
            }

            // Format it as a string with the desired format
            var formattedAmount = preApprovalAmount.ToString("N");

            return Ok(new { PreApprovalAmount = formattedAmount });
        }

        [HttpGet("GetPreApprovalAmountWithFica")]
        public IActionResult GetPreApprovalAmountWithFica(string firstName, string lastName, decimal annualIncome, decimal annualLiability, int loanTermYears, int ficaScore)
        {
            if (annualIncome <= 0 || annualLiability < 0 || (loanTermYears != 15 && loanTermYears != 30) || ficaScore < 300 || ficaScore > 850)
            {
                return BadRequest("Invalid input parameters.");
            }

            const int minimumFicaScore = 620; // Example minimum FICA score requirement

            if (ficaScore < minimumFicaScore)
            {
                return Ok(new { PreApprovalAmount = "0" });
            }

            decimal frontEndRatio;
            decimal backEndRatio;
            decimal preApprovalAmount;

            if (loanTermYears == 30)
            {
                frontEndRatio = 0.28m;
                backEndRatio = 0.36m;
            }
            else // 15-year fixed mortgage
            {
                frontEndRatio = 0.25m;
                backEndRatio = 0.33m;
            }

            var monthlyIncome = annualIncome / 12;
            var monthlyLiability = annualLiability / 12;

            var maxHousingExpense = monthlyIncome * frontEndRatio;
            var maxTotalDebt = (monthlyIncome * backEndRatio) - monthlyLiability;

            preApprovalAmount = Math.Min(maxHousingExpense, maxTotalDebt) * loanTermYears * 12;

            // Adjust pre-approval amount based on FICO score tiers
            if (ficaScore >= 800)
            {
                preApprovalAmount *= 1.08m; // 8% increase for exceptional credit
            }
            else if (ficaScore >= 740)
            {
                preApprovalAmount *= 1.05m; // 5% increase for very good credit
            }
            else if (ficaScore >= 670)
            {
                preApprovalAmount *= 1.0m; // No adjustment for good credit
            }
            else if (ficaScore >= 580)
            {
                preApprovalAmount *= 0.9m; // 10% decrease for fair credit
            }
            else
            {
                preApprovalAmount *= 0.8m; // 20% decrease for poor credit
            }

            if (preApprovalAmount <= 0)
            {
                preApprovalAmount = 0; // No pre-approval amount
            }

            // Format it as a string with the desired format
            var formattedAmount = preApprovalAmount.ToString("N");

            return Ok(new { PreApprovalAmount = formattedAmount });
        }


        [HttpGet("MonthlyMortgagePayment")]
        public IActionResult CalculateMonthlyMortgagePayment(decimal purchasePrice, decimal downPayment, decimal annualInterestRate, int loanTermYears)
        {
            var loanAmount = purchasePrice - downPayment;
            if (loanAmount <= 0 || annualInterestRate <= 0 || loanTermYears <= 0)
            {
                return BadRequest("Invalid input parameters.");
            }

            var monthlyPayment = MonthlyMortgagePayment(purchasePrice, downPayment, annualInterestRate, loanTermYears);

            // Format it as a string with the desired format
            var formattedAmount = monthlyPayment.ToString("N");

            return Ok(new { MonthlyMortgagePayment = formattedAmount });
        }

        [HttpGet("TotalMonthlyPayment")]
        public IActionResult CalculateTotalMonthlyPayment(decimal purchasePrice, decimal downPayment, decimal annualInterestRate, int loanTermYears, decimal yearlyTax, decimal yearlyInsurance)
        {
            var loanAmount = purchasePrice - downPayment;
            if (loanAmount <= 0 || annualInterestRate <= 0 || loanTermYears <= 0 || yearlyTax <= 0 || yearlyInsurance <= 0)
            {
                return BadRequest("Invalid input parameters.");
            }

            var monthlyTax = yearlyTax / 12;
            var monthlyInsurance = yearlyInsurance / 12;

            var monthlyMortgagePayment = MonthlyMortgagePayment(purchasePrice, downPayment, annualInterestRate, loanTermYears);

            // Format it as a string with the desired format
            var totalAmount = monthlyMortgagePayment + monthlyTax + monthlyInsurance;
            var formattedAmount = totalAmount.ToString("N");

            return Ok(new { TotalMonthlyPayment = formattedAmount });
        }


        private decimal MonthlyMortgagePayment(decimal purchasePrice, decimal downPayment, decimal annualInterestRate, int loanTermYears)
        {

            var loanAmount = purchasePrice - downPayment;
            var monthlyInterestRate = annualInterestRate / 12 / 100;
            var numberOfPayments = loanTermYears * 12;
            var monthlyMortgagePayment = (loanAmount * monthlyInterestRate) /
                                 (1 - (decimal)Math.Pow(1 + (double)monthlyInterestRate, -numberOfPayments));
            return monthlyMortgagePayment;
        }
    }
}

