<#
.SYNOPSIS
    Retrieve and download packages for a specified EPM set.

.DESCRIPTION
    This script interacts with the EPM API to retrieve a list of packages for a given EPM set.
    It checks the local repository for previously downloaded packages and downloads new versions.
    The details of downloaded packages are logged in a CSV file.

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder
    The local folder where packages will be downloaded.

.NOTES
    File: EPMPKGDownloader.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 1.0
    Last Modified: 12/2023
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [string]$tenant,

    [Parameter(Mandatory = $true, HelpMessage="Please provide the destination folder for downloaded packages")]
    [string]$destinationFolder
)
function Invoke-EPMRestMethod  {
<#
.SYNOPSIS
    Invokes a REST API method with automatic retry logic in case of transient failures.

.DESCRIPTION
    This function is designed to make REST API calls with automatic retries in case of specific errors, such as rate limiting.
    It provides a robust way to handle transient failures and ensures that the API call is retried a specified number of times.

.PARAMETER URI
    The Uniform Resource Identifier (URI) for the REST API endpoint.

.PARAMETER Method
    The HTTP method (e.g., GET, POST, PUT, DELETE) for the API call.

.PARAMETER Body
    The request body data to be sent in the API call (can be null for certain methods).

.PARAMETER Headers
    Headers to include in the API request.
#>
    param (
        [string]$URI,
        [string]$Method,
        [object]$Body,
        [hashtable]$Headers
    )

    $apiDelaySeconds = 120
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            # Convert Error message to Powershell Object
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            }
            else {
                throw "API call failed. $_"
            }

            # Error: EPM00000AE - Too many calls per 2 minute(s). The limit is 10
            if ( $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                Write-Host $ErrorDetailsMessage.ErrorMessage
                Write-Host "Retrying in $apiDelaySeconds seconds..."
                Start-Sleep -Seconds $apiDelaySeconds
                $retryCount++
            }
            else {
                throw "API call failed. ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
            }
        }
    }

    # If all retries fail, handle accordingly
    throw "API call failed after $RetryCount retries."
}

function Connect-EPM {
    <#
    .SYNOPSIS
    Connects to the EPM (Endpoint Privilege Manager) using the provided credentials and tenant information.

    .DESCRIPTION
    This function performs authentication with the EPM API to obtain the manager URL and authentication details.

    .PARAMETER credential
    The credential object containing the username and password.

    .PARAMETER epmTenant
    The EPM tenant name.

    .OUTPUTS
    A custom object with the properties "managerURL" and "auth" representing the EPM connection information.

    #>
    param (
        [pscredential]$credential,  # Credential object containing the username and password
        [string]$epmTenant          # EPM tenant name
    )

    # Convert credential information to JSON for authentication
    $authBody = @{
        Username = $credential.UserName
        Password = $credential.GetNetworkCredential().Password
        ApplicationID = "Powershell"
    } | ConvertTo-Json

    $authHeaders = @{
        "Content-Type" = "application/json"
    }

    $response = Invoke-EPMRestMethod -URI "https://$epmTenant.epm.cyberark.com/EPM/API/Auth/EPM/Logon" -Method 'POST' -Headers $authHeaders -Body $authBody

    # Return a custom object with connection information
    [PSCustomObject]@{
        managerURL = $($response.ManagerURL)
        auth       = $($response.EPMAuthenticationResult)
    }
}

function Get-EPMSetID {
    <#
    .SYNOPSIS
    Retrieves the ID and name of an EPM set based on the provided parameters.

    .DESCRIPTION
    This function interacts with the EPM API to retrieve information about sets based on the specified parameters.

    .PARAMETER managerURL
    The URL of the EPM manager.

    .PARAMETER authToken
    The authorization token for authentication.

    .PARAMETER setName
    The name of the EPM set to retrieve.

    .OUTPUTS
    A custom object with the properties "setId" and "setName" representing the EPM set information.

    #>
    param (
        [string]$managerURL,
        [hashtable]$Headers,
        [string]$setName
    )

    $sets = Invoke-EPMRestMethod -URI "$managerURL/EPM/API/Sets" -Method 'GET' -Headers $Headers
    
    $setId = $null

    # Check if $SetName is empty
    if ([string]::IsNullOrEmpty($setName)) {

        # Repeat until a valid set number is entered
        do {

            # List the available sets with numbers
            Write-Host "Available Sets:"
            $numberSets = 0
            foreach ($set in $sets.Sets) {
                Write-Host "$($numberSets + 1). $($set.Name)"
                $numberSets++
            }
        
            # Ask the user to choose a set by number
            $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"
        
            # Validate the chosen set number
            try {
                $chosenSetNumber = [int]$chosenSetNumber
        
                if ($chosenSetNumber -lt 1 -or $chosenSetNumber -gt $numberSets) {
                    Write-Error "Invalid set number. Please enter a number between 1 and $numberSets."
                } else {
                    # Set chosenSet based on the user's selection
                    $chosenSet = $sets.Sets[$chosenSetNumber - 1]
                    $setId = $chosenSet.Id
                    $setName = $chosenSet.Name
                }
            } catch {
                Write-Error "Invalid input. Please enter a valid number."
            }
        } until ($setId)
    }
    
    else {
        # List the sets with numbers
        foreach ($set in $sets.Sets) {
            # Check if setname matches with the configured set
            if ($set.Name -eq $SetName) {
                $setId = $set.Id
                break  # Exit the loop once the set is found
            }
        }
        if ([string]::IsNullOrEmpty($setId)) {
            Write-Error "$SetName : Invalid Set"
            return
        }
    }

    # Return a custom object with set information
    [PSCustomObject]@{
        setId   = $setId
        setName = $setName
    }
}

### Begin Script ###

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"

# Authenticate
$login = Connect-EPM -credential $credential -epmTenant $tenant

# Create a session header with the authorization token
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName


# Disable Progress Bar to improve download performance
$ProgressPreference = 'SilentlyContinue'

# Prepare Log file
$logFile = "$($destinationFolder)\package.csv"

if (-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
    Write-Host "Local EPM Repository folder created in $($destinationFolder)" -ForegroundColor Yellow
}

# Preparing the hashatable where to log details
$packageLog = @{}
if (Test-Path -Path $logFile) {
    Import-Csv -Path $logFile | ForEach-Object {
        $packageLog[$_.PackageName] = $_.PackageReleaseDate
    }
}

Write-Host "Getting Package List" -ForegroundColor Yellow
$packageList = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers/Packages" -Method 'GET' -Headers $sessionHeader

foreach ($package in $packageList.Packages) {
    if (-not $packageLog.ContainsKey($package.Name) -or $packageLog[$package.Name] -ne $package.ReleaseDate) {
        $dest = "$($destinationFolder)\$($package.Name)"

        Write-Host "$($package.Title) - $($package.Name)"
        Write-Host "$($package.Description)"
        Write-Host "Downloading latest version..."
        
        # Get Downlaod link
        $getPackageURL = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers/Packages/$($package.Id)/URL" -Method 'GET' -Headers $sessionHeader

        # Remove previous downloaded file if present
        if (Test-Path -Path $dest) {
            Remove-Item $dest
        }

        # Downlaod the package
        Invoke-WebRequest -Uri $getPackageURL -OutFile $dest        

        # Update packageLog
        $packageLog[$package.Name] = $package.ReleaseDate
    }
    else {
        Write-Host "$($package.Title) - $($package.Name) no new version available"
    }
}

# Saving Log
$packageLog.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        PackageName = $_.Key
        PackageReleaseDate = $_.Value
    }
} | Export-Csv -Path $logFile -NoTypeInformation


