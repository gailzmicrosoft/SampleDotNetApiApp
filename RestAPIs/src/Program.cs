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
            ConfigureConfiguration(builder);
            ConfigureKeyVault(builder);
            ConfigureServices(builder.Services, builder.Configuration);

            var app = builder.Build();
            ConfigureMiddleware(app);

            app.Run();
        }

        private static void ConfigureConfiguration(WebApplicationBuilder builder)
        {
            builder.Configuration.AddEnvironmentVariables();

            var environment = builder.Configuration["ENVIRONMENT"] ?? "Release";

            if (environment.Equals("Development", StringComparison.OrdinalIgnoreCase))
            {
                builder.Configuration
                    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                    .AddJsonFile($"appsettings.{environment}.json", optional: false, reloadOnChange: true);
            }
        }

        private static void ConfigureKeyVault(WebApplicationBuilder builder)
        {

            // For local testing, you need to set your access to key vault 
            // by adding new policy to allow you to have get, list, and update acess to key and secrets.
            // Retrieve secrets from Azure Key Vault
            // You may also need to set up network access policies for your Key Vault to allow access from your local machine or Azure services.

            var keyVaultUri = builder.Configuration["KEY_VAULT_URI"];
            if (string.IsNullOrEmpty(keyVaultUri))
            {
                throw new ArgumentNullException(nameof(keyVaultUri), "KEY_VAULT_URI not set.");
            }

            var secretClient = new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential());

            // Add or substract secrets to configuration based on your own architecture
            var secrets = new[]
            {
                "azure-storage-account-name",
                "azure-storage-blob-container-name",
                "form-recognizer-endpoint",
                "form-recognizer-key",
                "cosmos-db-endpoint",
                "cosmos-db-account-key",
                "cosmos-db-name",
                "cosmos-db-container-name",
                "x-api-key"
            };

            foreach (var secret in secrets)
            {
                builder.Configuration[secret] = secretClient.GetSecret(secret).Value.Value;
            }
        }

        private static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            services.AddControllers();
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
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
        }

        private static void ConfigureMiddleware(WebApplication app)
        {
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "RestAPIs v1");
                c.RoutePrefix = string.Empty;
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
        }
    }
}
