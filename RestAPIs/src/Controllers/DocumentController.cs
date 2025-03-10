
//################################################################################################################################
//# Author(s): Dr. Gail Zhou & GitHub CoPiLot
//# Last Updated: March 2025
//################################################################################################################################

using Azure;
using Azure.AI.FormRecognizer.DocumentAnalysis;
using Microsoft.AspNetCore.Mvc;
using RestAPIs.Capabilities;


// this module needs additional work. This is a draft 
namespace RestAPIs.Controllers
{
    //[Authorize]
    [ApiController]
    [Route("[controller]")]
    public class DocumentController : ControllerBase
    {
        private readonly ILogger<DocumentController> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _formRecognizerEndpoint;
        private readonly string _formRecognizerApiKey;

        public DocumentController(ILogger<DocumentController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;

            // Retrieve Form Recognizer Endpoint and API Key from the configuration
            _formRecognizerEndpoint = _configuration.GetValue<string>("form-recognizer-endpoint")
                                      ?? throw new ArgumentNullException("form-recognizer-endpoint is not set.");
            _formRecognizerApiKey = _configuration.GetValue<string>("form-recognizer-key")
                                    ?? throw new ArgumentNullException("form-recognizer-key is not set.");
        }

        [HttpGet("GetModels")]
        public async Task<IActionResult> GetModels()
        {
            var client = new DocumentModelAdministrationClient(new Uri(_formRecognizerEndpoint), new AzureKeyCredential(_formRecognizerApiKey));
            var models = client.GetDocumentModelsAsync();

            var modelList = new List<object>();

            try
            {
                await foreach (var model in models)
                {
                    modelList.Add(new
                    {
                        ModelId = model.ModelId,
                        Description = model.Description,
                        CreatedOn = model.CreatedOn
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred: {ex.Message}");
                return StatusCode(500, $"An internal server error occurred: {ex.Message}");
            }

            return Ok(modelList);
        }

        [HttpPost("AnalyzeDocument")]
        public async Task<IActionResult> AnalyzeDocument(IFormFile file, DocumentType documentType)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("Invalid file.");
            }

            try
            {
                // Read the file contents into a MemoryStream
                using var memoryStream = new MemoryStream();
                await file.CopyToAsync(memoryStream);
                memoryStream.Position = 0; // Reset the stream position to the beginning

                // TODO: Enhance the security access later 
                // add managed identity to the app service later. Assign Cognitive Services User role in Form Recognizer to the managed identity
                // Refer to LoanAppController.cs for the code to assign the role to the managed identity 

                var client = new DocumentAnalysisClient(new Uri(_formRecognizerEndpoint), new AzureKeyCredential(_formRecognizerApiKey));

                Dictionary<string, string> extractedData;
                switch (documentType)
                {
                    case DocumentType.IdDocument:
                        extractedData = await IdDocument(client, memoryStream);
                        break;
                    case DocumentType.TaxUsW2:
                        extractedData = await TaxUsW2(client, memoryStream);
                        break;
                    default:
                        extractedData = await GeneralDocument(client, memoryStream);
                        break;
                }

                return Ok(extractedData);
            }
            catch (RequestFailedException ex)
            {
                _logger.LogError($"Form Recognizer error: {ex.Status} - {ex.Message}");
                return StatusCode(ex.Status, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred: {ex.Message}");
                return StatusCode(500, $"An internal server error occurred: {ex.Message}");
            }
        }

        private async Task<Dictionary<string, string>> IdDocument(DocumentAnalysisClient client, Stream stream)
        {
            var operation = await client.AnalyzeDocumentAsync(WaitUntil.Completed, "prebuilt-idDocument", stream);
            var result = await operation.WaitForCompletionAsync();
            var extractedData = new Dictionary<string, string>();
            foreach (var kvp in result.Value.Documents[0].Fields)
            {
                extractedData[kvp.Key] = kvp.Value.Content;
            }
            return ExtractData(result.Value);
        }

        private async Task<Dictionary<string, string>> TaxUsW2(DocumentAnalysisClient client, Stream stream)
        {
            var operation = await client.AnalyzeDocumentAsync(WaitUntil.Completed, "prebuilt-tax.us.w2", stream);
            var result = await operation.WaitForCompletionAsync();
            return ExtractData(result.Value);
        }

        private async Task<Dictionary<string, string>> GeneralDocument(DocumentAnalysisClient client, Stream stream)
        {
            var operation = await client.AnalyzeDocumentAsync(WaitUntil.Completed, "prebuilt-document", stream);
            AnalyzeResult result = await operation.WaitForCompletionAsync();

            var extractedData = new Dictionary<string, string>();
            foreach (var document in result.Documents)
            {
                foreach (var field in document.Fields)
                {
                    if (field.Value.FieldType == DocumentFieldType.Dictionary)
                    {
                        foreach (var subField in field.Value.Value.AsDictionary())
                        {
                            extractedData[$"{field.Key}.{subField.Key}"] = subField.Value.Content;
                        }
                    }
                    else
                    {
                        extractedData[field.Key] = field.Value.Content;
                    }
                }
            }
            return extractedData;
        }

        private Dictionary<string, string> ExtractData(AnalyzeResult result)
        {
            var extractedData = new Dictionary<string, string>();
            foreach (var kvp in result.Documents[0].Fields)
            {
                extractedData[kvp.Key] = kvp.Value.Content;
            }

            return extractedData;
        }
    }
}





