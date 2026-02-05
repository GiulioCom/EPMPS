<#
.SYNOPSIS
    

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMBaseFunc.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 2
    Created: 05/2023
    Last Modified: 09/2025
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder 
)

<#
.SYNOPSIS
    Test Loader for EPMFunctions Module.
.DESCRIPTION
    Downloads the shared module from GitHub and imports it into the current session.
.INPUTS
    None.
.OUTPUTS
    Imports functions into the global scope.
#>
function Invoke-MainScript {
    [CmdletBinding()]
    param()
    # --- 1. Configuration ---
    $remoteUri  = "https://raw.githubusercontent.com/GiulioCom/EPMPS/main/Modules/EPMFunctions.psm1"
    $localDir   = Join-Path $env:LOCALAPPDATA "EPM_Scripts"
    $localPath  = Join-Path $localDir "EPMFunctions.psm1"

    # --- 2. Resource Optimization (Smart Download) ---
    # We check if the file exists so we don't hammer the network on every run.
    if (-not (Test-Path $localPath)) {
        Write-Host "Module not found locally. Downloading from GitHub..." -ForegroundColor Cyan
        
        # Ensure the directory exists
        if (-not (Test-Path $localDir)) { 
            New-Item -Path $localDir -ItemType Directory -Force | Out-Null 
        }

        try {
            # Streaming the download directly to disk is more memory-efficient 
            # than saving it to a variable first.
            Invoke-RestMethod -Uri $remoteUri -OutFile $localPath -ErrorAction Stop
            Write-Host "Download successful." -ForegroundColor Green
        } catch {
            Write-Error "Failed to download EPMFunctions. Check the URL or connection."
            return # Stop execution if we can't get the core functions
        }
    }

    # --- 3. Import the Module ---
    # -Force ensures that if you changed the file, the new version is loaded.
    Import-Module -Name $localPath -Force
}
<#
# --- 4. Test the Functionality ---
# Assuming your EPMFunctions.psm1 has a function named 'Get-EPMStatus'
if (Get-Command Get-EPMStatus -ErrorAction SilentlyContinue) {
    Get-EPMStatus
} else {
    Write-Warning "Module loaded, but 'Get-EPMStatus' function was not found."
}
#>

Invoke-MainScript

### Begin Script ###
$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path -leaf $MyInvocation.MyCommand.Path))
## Prepare log if needed
if ($log) {
    $LogFilePath = Initialize-Log -LogFolder $LogFolder
    Write-Log "Logging enabled. File: $LogFilePath" INFO
}

Write-Box "$ScriptName"

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"
if ($null -eq $credential) {
    Write-Log "Failed to get credentials..." ERROR
    exit
}
# Authenticate
$login = Connect-EPM -credential $credential -epmTenant $tenant

# Create a session header with the authorization token
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

Write-Log $login.managerURL INFO
Write-Log $set.SetName INFO
Write-Log $set.SetId INFO

<#
Write-Log "This is an INFO" INFO
Write-Log "This is a WARNING" WARN
Write-Log "This is an ERROR" ERROR
Write-Log "This is an INFO" INFO -ForegroundColor DarkCyan
#>

#Example Request 

# Test GetPolicies
#$policies = Get-EPMPolicies -limit 50
#$policies

# Test GetEndpoints
#$endpoints = Get-EPMEndpoints -limit 2
#$endpoints

# Test GetComputers
#$computers = Get-EPMComputers -limit 2
#$computers


# Wrong Body
#$policyFilter = @{
#    "filter" = "Active EQ true AND Action IN 3,4 AND PolicyType EQ ADV_WIN"
#}  | ConvertTo-Json
#
#Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policyFilter


#$retryCount = 0
#do {
    # All computers
#    $getComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers" -Method 'GET' -Headers $sessionHeader
    #$getComputerList | ConvertTo-Json
#    Write-Log $getComputerList INFO
#    $retryCount++
#} while ($retryCount -lt 20)

# Disconnected Computers
#$URLquery = "?`$filter=Status eq 'Disconnected'"
#$getDisconnectedComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers$URLQuery" -Method 'GET' -Headers $sessionHeader
#$getDisconnectedComputerList | ConvertTo-Json

#$getComputerList = Get-EPMComputers

#$OutputPath = "EPM_Computers_List.csv"

# Input is assumed to be the array property of the API result
#$ComputersArray = $getComputerList.Computers

# 1. Pipeline the objects directly to the export cmdlet.
#$ComputersArray | Export-Csv -Path $OutputPath -NoTypeInformation

#Write-Host "Successfully exported $($ComputersArray.Count) computers to $OutputPath" -ForegroundColor Green