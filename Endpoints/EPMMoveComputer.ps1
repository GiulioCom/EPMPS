<#
.SYNOPSIS
    Move Computers from one SET to another

.DESCRIPTION
    Move Computers from one SET to another reading the input from csv having the list of computer,setName

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER delete
    Flag to enabled computer deletion

.NOTES
    File: EPMMoveComputers.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 02/2025
    Last Modified: 09/2025
    - 26/09/2025: Improve managent fo more than 5000 device

.EXAMPLE
    .\EPMMoveComputers.ps1 -username user@domain -tenant eu -set "Set Name" -computerList "file" -destSetName "dest Set Name" -log
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(Mandatory = $true, HelpMessage="CSV file list of computers")]
    [string]$computerList,

    [Parameter(Mandatory = $true, HelpMessage="Destination Set")]
    [string]$destSetName,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder
)

## Write-Host Wrapper and log management
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$message,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$severity,

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$ForegroundColor
    )
    
    $expSeverity = $severity
    $exceedingChars = 5-$severity.Length
    
    while ($exceedingChars -ne 0) {
        $expSeverity = $expSeverity + " "
        $exceedingChars--
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$expSeverity] $message"

    switch ($severity) {
        "INFO" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Green"
            }
        }
        "WARN" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Yellow"
            }
        }
        "ERROR" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Red"
            }
        }
    }

    Write-Host $logMessage -ForegroundColor $ForegroundColor

    if ($log) {
        Add-Content -Path $logFilePath -Value $logMessage
    }
}

function Write-Box {
    param (
        [string]$title
    )
    
    # Create the top and bottom lines
    $line = "-" * $title.Length

    # Print the box
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
    Write-Log "| $title |" -severity INFO -ForegroundColor Cyan
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
}

## Invoke-RestMethod Wrapper
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
function Invoke-EPMRestMethod {
    param (
        [string]$URI,
        [string]$Method,
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$MaxRetries = 3
    #    [int]$RetryDelay = 120
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            $ErrorDetailsMessage = $null

            # Extract API error details if available
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try {
                    $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "Failed to parse error message as JSON. Raw message: $($_.ErrorDetails.Message)" WARN
                }
            }

            # Handle rate limit error (EPM00000AE)
            if ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                # Define a regex pattern to find numbers followed by "minute(s)"
                $pattern = "\d+\s+minute"

                # Search for the pattern in the error message
                $match = [regex]::Match($ErrorDetailsMessage.ErrorMessage, $pattern)

                # If a match is found, extract the number
                if ($match.Success) {
                    $minutes = [int]($match.Value -replace '\s+minute', '')
                    # Convert minutes to seconds and update the RetryDelay variable
                    [int]$RetryDelay = $minutes * 60
                }

                Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds..." WARN
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } else {
                # Handle Body possible filter error 
                if ($ErrorDetailsMessage.ErrorCode -eq "EPM000002E" -and $null -ne $Body) {
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    Write-Log "Please verify the filter body if present, as it could be the cause of this error code." ERROR
                    throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                } else {
                    # Log error only if it's NOT the handled EPM00000AE error
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                }
            }
        }
    }

    # If all retries fail, log and throw an error
    Write-Log "API call failed after $MaxRetries retries. URI: $URI" ERROR
    throw "API call failed after $MaxRetries retries."
}

## EPM RestAPI Wrappers
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
function Connect-EPM {
    param (
        [Parameter(Mandatory = $true)]
        [pscredential]$credential,  # Credential object containing the username and password

        [Parameter(Mandatory = $true)]
        [string]$epmTenant          # EPM tenant name
    )

    # Convert credential information to JSON for authentication
    $authBody = @{
        Username      = $credential.UserName
        Password      = $credential.GetNetworkCredential().Password
        ApplicationID = "Powershell"
    } | ConvertTo-Json -Depth 3

    $authHeaders = @{
        "Content-Type" = "application/json"
    }

    try {
        # Write-Log "Attempting to connect to EPM tenant: $epmTenant" INFO
        $response = Invoke-EPMRestMethod -URI "https://$epmTenant.epm.cyberark.com/EPM/API/Auth/EPM/Logon" -Method 'POST' -Headers $authHeaders -Body $authBody

        # Ensure the response contains the expected fields
        if (-not $response -or -not $response.ManagerURL -or -not $response.EPMAuthenticationResult) {
            throw "EPM authentication failed: Missing expected response fields."
        }

        # Write-Log "Successfully connected to EPM tenant: $epmTenant" INFO

        # Return a custom object with connection information
        return [PSCustomObject]@{
            managerURL = $response.ManagerURL
            auth       = $response.EPMAuthenticationResult
        }
    }
    catch {
        Write-Log "Failed to connect to EPM tenant: $epmTenant. Error: $_" ERROR
        throw "Error connecting to EPM: $_"
    }
}

<#
.SYNOPSIS
Retrieves the ID and name of an EPM set based on the provided parameters.

.DESCRIPTION
This function interacts with the EPM API to retrieve information about sets based on the specified parameters.

.PARAMETER managerURL
The URL of the EPM manager.

.PARAMETER Headers
The authorization headers.

.PARAMETER setName
The name of the EPM set to retrieve.

.OUTPUTS
A custom object with the properties "setId" and "setName" representing the EPM set information.
#>
function Get-EPMSetID {
    param (
        [Parameter(Mandatory = $true)]
        [string]$managerURL,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$setName
    )

    # Retrieve list of sets
    try {
        #Write-Log "Retrieving EPM Sets from: $managerURL" INFO
        $sets = Invoke-EPMRestMethod -URI "$managerURL/EPM/API/Sets" -Method 'GET' -Headers $Headers

        if (-not $sets -or -not $sets.Sets) {
            throw "No sets retrieved from EPM."
        }
    }
    catch {
        Write-Log "Failed to retrieve EPM Sets. Error: $_" ERROR
        throw "Could not retrieve EPM sets."
    }

    #$setId = $null

    # If setName is provided, search for it directly
    if (-not [string]::IsNullOrEmpty($setName)) {
        $selectedSet = $sets.Sets | Where-Object { $_.Name -eq $setName } | Select-Object -First 1

        if ($selectedSet) {
            return [PSCustomObject]@{
                setId   = $selectedSet.Id
                setName = $selectedSet.Name
            }
        } else {
            Write-Log "Error: Set '$setName' not found in EPM." ERROR
            throw "Invalid Set Name: $setName"
        }
    }

    # If no setName is provided, prompt the user to select one
    #Write-Log "No set name provided. Listing available sets for selection..." INFO

    if ($sets.Sets.Count -eq 0) {
        Write-Log "No sets available in EPM." ERROR
        throw "No sets found. Cannot proceed."
    }

    Write-Box "Available Sets:" INFO

    for ($i = 0; $i -lt $sets.Sets.Count; $i++) {
        Write-Log "$($i + 1). $($sets.Sets[$i].Name)" INFO DarkCyan
    }

    # Prompt user for input with max retries
    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"

        try {
            $chosenSetNumber = [int]$chosenSetNumber

            if ($chosenSetNumber -ge 1 -and $chosenSetNumber -le $sets.Sets.Count) {
                $chosenSet = $sets.Sets[$chosenSetNumber - 1]
                return [PSCustomObject]@{
                    setId   = $chosenSet.Id
                    setName = $chosenSet.Name
                }
            } else {
                Write-Log "Invalid selection. Please enter a number between 1 and $($sets.Sets.Count)." ERROR
            }
        }
        catch {
            Write-Log "Invalid input. Please enter a valid number." ERROR
        }
    }

    throw "Maximum attempts reached. Exiting set selection."
}

<#
.SYNOPSIS
    Retrieves a list of EPM Computers from a CyberArk EPM server, handling pagination automatically.

.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get computers.
    It automatically manages pagination by making multiple API calls if the total number
    of computers exceeds the API's maximum limit (5000). The function merges all
    computers into a single PSCustomObject for easy management.

.PARAMETER limit
    The maximum number of computers to retrieve per API call. The default is 5000,
    which is the maximum allowed by the CyberArk EPM API.

.EXAMPLE
    Get-EPMTotalCount -limit 500

.OUTPUTS
    This function returns an object containing the merged computers and metadata.
    The object has the following properties:
        - Computers: An array of all policy objects.
        - TotalCount: The total number of policies on the server.

.NOTES
    This function requires a valid session header and manager URL to be accessible
    in the execution context. It uses Invoke-EPMRestMethod.
#>
Function Get-EPMComputers {
        param (
        [int]$limit = 5000  # Set limit to the max size if not declared
    )

    $mergeComputers = [PSCustomObject]@{
        Computers = @()
        TotalCount = 0
    }

    $offset = 0             # Offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        $getComputers = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers?offset=$offset&limit=$limit" -Method 'GET' -Headers $sessionHeader
        
        $mergeComputers.Computers += $getComputers.Computers    # Merge the current computer list
        $mergeComputers.TotalCount = $getComputers.TotalCount   # Update the TotalCount

        $total = $getComputers.TotalCount   # Update the total with the real total
        $offset += $getComputers.Computers.Count

        # Progress  Bar
        $Percent = [int](($offset / $total) * 100)
        Write-Progress -Activity "Retrieving Computers $($total) total" -Status "Retrieved: $offset Computers" -PercentComplete $Percent
    }
    Write-Progress -Activity "Retrieving Computers $($total) total"  -Status "Completed: Successfully retrieved $($mergeComputers.TotalCount) Computers" -PercentComplete 100 -Completed
    
    return $mergeComputers
}

### Begin Script ###

## Prepare log folder and file
# Set default log folder if not provided
if (-not $PSBoundParameters.ContainsKey('logFolder')) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $logFolder = Join-Path $scriptDirectory "log"
}

# Ensure the log folder exists
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force
}

# Create log file name based on timestamp and script name
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$logFileName = "$timestamp`_$scriptName.log"
$logFilePath = Join-Path $logFolder $logFileName

Write-Box "$scriptName"

# Check if the computer list file exists
if (-Not (Test-Path -Path $computerList -PathType Leaf)) {
    Write-Log "The specified file '$computerList' does not exist." ERROR
    exit 1
}

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"

# Authenticate
$login = Connect-EPM -credential $credential -epmTenant $tenant

# Create a session header with the authorization token
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
    "Content-Type" = "application/json"
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

# Read the list of computer names
$computerNamesFile = Get-Content -Path $computerList

# Get Destination SET data
$destSet = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $destSetName

# Get computers list
#$getComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers?limit=5000" -Method 'GET' -Headers $sessionHeader
$getComputerList = Get-EPMTotalCount

<#
$getComputerList = @'
[
    {
        "AgentId": "c15764f3-d9ae-4ee0-83e9-f1f5806f91ca",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-14T16:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-11T10:56:35.38",
        "LoggedIn": ""
    },
    {
        "AgentId": "d5f92e1c-bf1b-48f3-9eae-7c5a3e8e642e",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-2",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-15T12:45:09.257",
        "Status": "Connected",
        "LastSeen": "2024-04-11T09:56:35.38",
        "LoggedIn": "user1"
    },
    {
        "AgentId": "e6b14235-2f11-4c8e-bcf2-9e3489776a3c",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-20T08:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-10T10:56:35.37",
        "LoggedIn": ""
    },
    {
        "AgentId": "e6b14234-2f11-4c8e-bcf2-9e3489776a3c",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-20T08:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-10T10:56:34.37",
        "LoggedIn": ""
    }
]
'@ | ConvertFrom-Json
#>

# Initialize the mapping for the received computer details from console
$consoleComputersList = @{}
foreach ($compData in $getComputerList.Computers) {
    $consoleComputersList[$compData.ComputerName] = $compData.AgentId
}

$computerIds = @()

foreach ($computerName in $computerNamesFile) {
    # Find the computer in $getComputerList
    if ($consoleComputersList.ContainsKey($computerName)) {
        $computerIds += $consoleComputersList[$computerName]
        Write-Log "Computer found: $computerName (AgentId: $($consoleComputersList[$computerName]))" INFO
    } else {
        Write-Log "Computer '$computerName' from Set '$setName' not found in the system." ERROR
    }

    # Stop if the array reaches 500 entries
    if ($computerIds.Count -ge 500) {
        Write-Log "Limit reached: 500 computers processed. Stopping further processing." WARN
        break
    }
}

# Move Computer

# Prepare Body
$moveComputerBody = @{
    "computerIds" = $computerIds
    "destSetId"   = $destSet.setId
} | ConvertTo-Json -Depth 10  # Convert to JSON for API usage

$moveComputer = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers/RedirectAgents" -Method 'POST' -Headers $sessionHeader -Body $moveComputerBody

Write-Log "Computer moved to Set $destSeName"