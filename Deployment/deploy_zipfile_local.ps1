
################################################################################################################################
# Author(s): Dr. Gail Zhou & GitHub CoPiLot
# Last Updated: March 2025
################################################################################################################################
# how to run: 
# cd Deployment 
# .\deploy_zipfile_local.ps1

# set up path and file name
$scriptPath = (Get-Location).Path
Set-Location $scriptPath 

$zipFile = Read-Host -Prompt "Enter the name of the zip file to build and deploy (e.g. sample_app.zip)"

Write-Host "zip File: " $zipFile

$zipFilePath = "$scriptPath\$zipFile"

Write-Host "zip File Path: " $zipFilePath


# Check if the zip file exists
if (-Not (Test-Path $zipFilePath)) {
    Write-Error "The specified zip file does not exist: $zipFilePath"
    exit 1
}


# Deploy to Azure App Services

az login

# get user input
$resourceGroup = Read-Host -Prompt "Enter your resource group name"
$appServiceName = Read-Host -Prompt "Enter your app service name"

# this is deprecated command. no replacement for .zip deploymnet. 
# https://learn.microsoft.com/en-us/azure/app-service/deploy-zip?tabs=cli
az webapp deploy --resource-group $resourceGroup --name $appServiceName --src-path $zipFilePath


