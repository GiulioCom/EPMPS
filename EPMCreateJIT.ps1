<#
.SYNOPSIS
    Create JIT (Just-in-Time) policies based on manual request events.

.DESCRIPTION
    1. Retrieve events from EPM that occurred after the last stored timestamp.
    2. Create JIT policies in EPM based on the retrieved events.
    3. Update the log file with the latest event timestamp.

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.NOTES
    File: EPMCreateJIT.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.2 - POC
    Date: 01/2024

.RELEASE NOTES
    01/2024 - Initial Version
    12/2024 - Adding Logs
    12/2024 - Improve last date management
    11/2025 - Update core functions

.EXAMPLE
    1. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu"
        Check events in the set, no log created, lastEventFile stored in the script current folder \lastEvents
    2. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -log -logFolder "C:\Logs" -lastEventFolder "C:\Events"
        Check events in the set, create log in the custom folder C:\Logs and last event file in C:\Events\
    3. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -log -lastEventFolder "C:\Events"
        Check events in the set, create log in the "current script folder\log" and last event file in "C:\Events"
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName = "",

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(HelpMessage = "Please provide the folder to store the last event date detail.")]
    [string]$lastEventFolder
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
                # Regex pattern to find numbers followed by "minute(s)"
                $pattern = "\d+\s+minute"
                $match = [regex]::Match($ErrorDetailsMessage.ErrorMessage, $pattern)
                if ($match.Success) {
                    $minutes = [int]($match.Value -replace '\s+minute', '')
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
Connects to the EPM (Enterprise Password Vault) using the provided credentials and tenant information.

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

function Resolve-Folder {
    param (
        [string]$ProvidedFolder,
        [string]$DefaultSubFolder
    )

    # Determine the script directory or fallback to current directory
    $scriptDirectory = if ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        Get-Location
    }

    # Use the provided folder or create a default subfolder
    $resolvedFolder = if ($ProvidedFolder) {
        $ProvidedFolder
    } else {
        Join-Path $scriptDirectory $DefaultSubFolder
    }

    # Ensure the folder exists
    if (-not (Test-Path $resolvedFolder)) {
        New-Item -Path $resolvedFolder -ItemType Directory -Force | Out-Null
    }

    return $resolvedFolder
}

function Remove-InvalidCharacters {
    param (
        [Parameter(Mandatory)]
        [string]$InputString
    )

    # Define invalid characters for file names
    $invalidCharacters = '[\\/:*?"<>|[\]]'

    # Remove invalid characters
    $sanitizedString = $InputString -replace $invalidCharacters, ''

    return $sanitizedString
}

function Add-msToTimestamp {
    param (
        [string]$timestamp
    )

    if ($timestamp -match '^(?<Date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?<Milliseconds>\d+))?(?<Zone>Z)$') {
        
        $datePart = $Matches['Date']
        $milliseconds = $Matches['Milliseconds']
        #$zone = $Matches['Zone']

        # Ensure milliseconds are always three digits
        $milliseconds = if ($null -eq $milliseconds) { "000" } else { $milliseconds.PadRight(3, '0') }

        $datems = "$datePart.$milliseconds"
        
        # Convert to integer and add 1 millisecond
        $newDate = [datetime]::ParseExact($datems, "yyyy-MM-ddTHH:mm:ss.fff", $null).AddMilliseconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        return $newDate
           
    } else {
        throw "Invalid timestamp format: $timestamp"
    }
}

# Logging setup
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
if ($log) {
    $resolvedLogFolder = Resolve-Folder -ProvidedFolder $logFolder -DefaultSubFolder "log"

    # Create log file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "$timestamp`_$scriptName.log"
    $logFilePath = Join-Path $resolvedLogFolder $logFileName

    Write-Log "Logging enabled. Log file: $logFilePath" INFO
}
## Log file done

Write-Box "$scriptName"

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

# Last event tracking setup
$resolvedLastEventFolder = Resolve-Folder -ProvidedFolder $lastEventFolder -DefaultSubFolder "EPMJIT_lastEvents"
$lastEventFile = Join-Path $resolvedLastEventFolder "lastEvents.txt"

# Set the last events, by default 1 month
$lastEventTimestamp = (Get-Date).AddMonths(-1).ToString('yyyy-MM-ddTHH:mm:ss.ffZ')

# Check if the file exists
if (Test-Path $lastEventFile -PathType Leaf) {
    Write-Log "Found last events file: $lastEventFile" INFO
    # Read the first line from the file
    $firstLine = Get-Content $lastEventFile -First 1

    # Define a regex pattern for the timestamp format "2024-01-12T16:51:32.303Z"
    $timestampPattern = '^(?<Date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.)(?<Milliseconds>\d+)(?<Zone>Z)$'

    # Check if the first line matches the timestamp pattern
    if ($firstLine -match $timestampPattern) {
        # Assign the timestamp to a variable
        $lastEventTimestamp = $matches[0]

        # Display the timestamp
        Write-Log "Searching Manual Request events from $lastEventTimestamp" INFO
    } else {
        Write-Log "$firstLine does not match the expected timestamp format. Starting the event search from $lastEventTimestamp" WARN
    }
} else {
    Write-Log "$($lastEventFile): The file does not exist. Starting the event search from $lastEventTimestamp" WARN
}

# Get Events
$eventsFilter = @{
    "filter" = "eventDate GE $lastEventTimestamp AND eventType IN ManualRequest"
}  | ConvertTo-Json

$GetEvents = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Events/Search?limit=1000&sortDir=asc" -Method 'POST' -Headers $sessionHeader -Body $eventsFilter

# Write-Log $($GetEvents | Convertto-Json -Depth 10) INFO

if ($GetEvents.filteredCount -gt 0) {
    Write-Log "Found $($GetEvents.filteredCount) Manual Request from $lastEventTimestamp" INFO

    foreach ($EPMEvent in $GetEvents.events) {

        # Create JIT policy
        Write-Log "Processing $count of $($GetEvents.filteredCount) Manual Request for '$($EPMEvent.userName)' on '$($EPMEvent.computerName)' - Justification '$($EPMEvent.justification)'" INFO
        
        $policyDetails = @{
            "Name" = "JIT $($EPMEvent.userName) on $($EPMEvent.computerName)"
            "Description" =  $($EPMEvent.justification)
            "IsActive" = $true
            "IsAppliedToAllComputers" = $false
            "PolicyType" = 40
            "Action" = 20
            "Duration" = "1"
            "KillRunningApps" = $true
            "Audit" = $true
            "Executors" = @(
                @{
                    "Id" = "$($EPMEvent.agentId)"
                    "Name" = "$($EPMEvent.computerName)"
                    "ExecutorType" = 1
                }
            )
            "Accounts" = @(
                @{
                    "SamName" = "$($EPMEvent.userName)"
                    "DisplayName" = "$($EPMEvent.userName)"
                    "AccountType" = 1
                }
            )
            "IncludeADComputerGroups" = @()
            "TargetLocalGroups" = @(
                @{
                    "AccountType" = 0
                    "DisplayName" = "Administrators"
                }
            )
        } | ConvertTo-Json

        $createJIT = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $policyDetails
        if ($createJIT.id) {
            Write-Log "$($createJIT.Name) policy created" INFO
        } else {
            Write-Log "Error creating policy for $($EPMEvent.userName) on $($EPMEvent.computerName)" ERROR
        }
        
        # Update lastevents file
        $newfirstEventDate = Add-msToTimestamp -timestamp $EPMEvent.firstEventDate
        Write-Log "The last event date $($EPMEvent.firstEventDate), save last event date $newfirstEventDate in $lastEventFile" INFO
        $newfirstEventDate | Set-Content -Path $lastEventFile -Force
    }
} else {
    Write-Log "No new Manual Request from $lastEventTimestamp" INFO
}
