################################################################################################################################
# Author(s): Dr. Gail Zhou & GitHub CoPiLot
# Last Updated: March 2025
################################################################################################################################
# how to run: 
# cd Deployment 
# .\deploy_zipfile_github.ps1

# The PowerShell script downloads a zip file from a given URL and deploys it to an Azure App Service using the Azure CLI.
# The script first logs in to Azure using the az login command. It then prompts the user for the resource group name and app service name.
# After that, it downloads the zip file from the specified URL using the Invoke-WebRequest cmdlet and saves it to a temporary file.
# Finally, it deploys the zip file to the specified Azure App Service using the Publish-AzWebApp cmdlet and cleans up the temporary file.
#


# Use GitHub Zip file 
$zipFileUrl = 'https://raw.githubusercontent.com/gailzmicrosoft/SampleSecureApiApp/main/Deployment/sample_app.zip'

# Set the path to the temporary file
$zipFilePathTmp = [System.IO.Path]::GetTempFileName()
Write-Host "Temporary file path: $zipFilePathTmp"
$zipFilePathTmp = [System.IO.Path]::ChangeExtension($zipFilePathTmp, '.zip')
Write-Host "Temporary file path with .zip: $zipFilePathTmp"

az login
# get user input
$resourceGroup = Read-Host -Prompt "Enter your resource group name"
$appServiceName = Read-Host -Prompt "Enter your app service name"


# Download the zip file
Invoke-WebRequest -Uri $zipFileUrl -OutFile $zipFilePathTmp

# Deploy the zip file
Publish-AzWebApp -ResourceGroupName $resourceGroup -Name $appServiceName -ArchivePath $zipFilePathTmp

# Clean up the downloaded zip file
Remove-Item $zipFilePathTmp

