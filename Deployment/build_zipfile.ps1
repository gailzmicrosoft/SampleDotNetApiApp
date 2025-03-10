
################################################################################################################################
# Author(s): Dr. Gail Zhou & GitHub CoPiLot
# Last Updated: March 2025
################################################################################################################################
# Description: This script builds a .NET project and creates a .zip file for deployment.
# This script is intended to be run in the Deployment folder.
# It builds the project located in the RestAPIs/src folder and creates a .zip file in the RestAPIs/deploy folder.
# The script uses the .NET CLI to publish the project and the Compress-Archive cmdlet to create the .zip file.
# The script prompts the user for the name of the .zip file to create.
# The script removes any existing .zip file with the same name before creating a new one.
# The script assumes that the .NET SDK is installed and available in the system PATH.
# The script assumes that the Compress-Archive cmdlet is available in the system PATH.
################################################################################################################################
#how to run: 
# cd Deployment 
# .\build_zipfile.ps1

# set up path
$projectDir = "..\RestAPIs\src"
$outputDir = "..\RestAPIs\deploy"
$scriptPath = (Get-Location).Path

$zipFile = Read-Host -Prompt "Enter the name of the zip file to build and deploy (e.g. sample_app.zip)"

# Remove $zipFile if it exists
$zipFilePath = "$scriptPath\$zipFile"
if (Test-Path $zipFilePath) {
    Remove-Item -Force $zipFilePath
}

# Step 1: Build the project
dotnet publish $projectDir -c Release -o $outputDir

# Step 2: Create a .zip file
Set-Location $outputDir
Compress-Archive -Path * -DestinationPath $zipFilePath

Set-Location $scriptPath 

