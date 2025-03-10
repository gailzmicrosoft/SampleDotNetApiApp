using Microsoft.OpenApi.Models;
using RestAPIs.Middleware;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace RestAPIs
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Configuration.AddEnvironmentVariables(); //
     
            // Load environment-specific appsettings.json
            var environment = builder.Configuration["ENVIRONMENT"];
            if (string.IsNullOrEmpty(environment))
            {
                environment = "Release"; // Default value if ENVIRONMENT is not set
            }

            //only execute below if the environment is development 
            if (environment.Equals("Development", StringComparison.OrdinalIgnoreCase))
            {
                builder.Configuration
               .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
               .AddJsonFile($"appsettings.{environment}.json", optional: false, reloadOnChange: true);
            }

            // For local testing, you need to set your access to key vault 
            // by adding new policy to allow you to have get, list, and update acess to key and secrets.
            // Retrieve secrets from Azure Key Vault
            var keyVaultUri = builder.Configuration["KEY_VAULT_URI"];
            if (string.IsNullOrEmpty(keyVaultUri))
            {
                throw new ArgumentNullException(nameof(keyVaultUri), "KEY_VAULT_URI not set.");
            }

            // Create a SecretClient to access the Key Vault
            var secretClient = new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential());

            // Retrieve secrets
            var azureStorageAccountName = secretClient.GetSecret("azure-storage-account-name").Value.Value;
            var azureStorageBlobContainerName = secretClient.GetSecret("azure-storage-blob-container-name").Value.Value;
            var formRecognizerEndpoint = secretClient.GetSecret("form-recognizer-endpoint").Value.Value;
            var formRecognizerKey = secretClient.GetSecret("form-recognizer-key").Value.Value;
            var cosmosDbEndpoint = secretClient.GetSecret("cosmos-db-endpoint").Value.Value;
            var cosmosDbAccountKey = secretClient.GetSecret("cosmos-db-account-key").Value.Value;
            var cosmosDbName = secretClient.GetSecret("cosmos-db-name").Value.Value;
            var cosmosDbContainerName = secretClient.GetSecret("cosmos-db-container-name").Value.Value;
            var apiKey = secretClient.GetSecret("x-api-key").Value.Value;

            // Add secrets to configuration
            builder.Configuration["azure-storage-account-name"] = azureStorageAccountName;
            builder.Configuration["azure-storage-blob-container-name"] = azureStorageBlobContainerName;
            builder.Configuration["form-recognizer-endpoint"] = formRecognizerEndpoint;
            builder.Configuration["form-recognizer-key"] = formRecognizerKey;
            builder.Configuration["cosmos-db-endpoint"] = cosmosDbEndpoint;
            builder.Configuration["cosmos-db-account-key"] = cosmosDbAccountKey;
            builder.Configuration["cosmos-db-name"] = cosmosDbName;
            builder.Configuration["cosmos-db-container-name"] = cosmosDbContainerName;
            builder.Configuration["x-api-key"] = apiKey;


            //// Add Application Insights telemetry
            //builder.Services.AddApplicationInsightsTelemetry(options =>
            //{
            //    options.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
            //});

            // Add services to the container.
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("x-api-key", new OpenApiSecurityScheme
                {
                    Description = "API Key needed to access the endpoints. x-api-key: Your_API_Key",
                    In = ParameterLocation.Header,
                    Name = "x-api-key",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "x-api-key-Scheme"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "x-api-key"
                            },
                            Scheme = "ApiKeyScheme",
                            Name = "x-api-key",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });
            });


          

            var app = builder.Build();
     
            //always use Swagger. 
            app.UseSwagger();
            //app.UseSwaggerUI(); // removed becasue this method is overriden below
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "RestAPIs v1");
                c.RoutePrefix = string.Empty; // Set Swagger UI at the app's root
            });


            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.UseMiddleware<ApiKeyMiddleware>();

            app.MapControllers();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                //app.UseHsts(); // Enforces the use of HTTPS by adding HSTS headers to responses, enhancing security.
            }

            app.Run();
        }
    }
}
