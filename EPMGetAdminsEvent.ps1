<#
.SYNOPSIS
    Example script to get Set Admins Events.

.DESCRIPTION

.PARAMETER username
    Mandatory: Yes
    The EPM username (e.g., user@domain).

.PARAMETER setName
    Mandatory: No
    The name of the EPM set.

.PARAMETER tenant
    Mandatory: Yes
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder
    Mandatory: Conditional
    Specifies the folder where data will be stored. This parameter is mandatory in Audit Mode.

.EXAMPLE

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 02/2024
    Last Modified: 05/2024
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
function Invoke-EPMRestMethod {
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
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 120
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            #$errorMessage = $_.Exception.Message
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
            
            if ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                # Handle rate limit error (EPM00000AE)
                Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds..." WARN
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } elseif ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM000002E"){
                # Handle Error while upload a policy.
                Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                
                # Return a custom object with error info and a flag to indicate failure.
                return [PSCustomObject]@{
                    Success = $false
                    ErrorCode = $ErrorDetailsMessage.ErrorCode
                    ErrorMessage = $ErrorDetailsMessage.ErrorMessage
                }
            } else {
                Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                # Thow the Blocking error
                throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
            }
        }
    }

    # If all retries fail, log and throw an error
    if ($retryCount -eq $MaxRetries) {
        Write-Log "API call failed after $MaxRetries retries. URI: $URI" ERROR
        throw "API call failed after $MaxRetries retries."
    }
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

# Function to log messages to console and file
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
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$severity] - $message"

    switch ($severity) {
        "INFO" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Green"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
        "WARN" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Yellow"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
        "ERROR" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Red"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
    }

    if ($log) {
        Add-Content -Path $logFilePath -Value $logMessage
    }
}

function Write-Box {
    param (
        [string]$title
    )
    
    # Calculate the length of the title
    $titleLength = $title.Length

    # Create the top and bottom lines
    $line = "-" * $titleLength

    # Print the box
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
    Write-Log "| $title |" -severity INFO -ForegroundColor Cyan
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
}

function Resolve-Folder {
    param (
        [string]$ProvidedFolder
    )

    $resolvedFolder = $ProvidedFolder

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
Write-Box "Analyzing Set $($set.setName)"

# Last event tracking setup
#$resolvedLastEventFolder = Resolve-Folder -ProvidedFolder $lastEventFolder
# Create or update last event file

$lastEventFileName = Remove-InvalidCharacters -InputString "$($set.setName)-lastEvents.txt"
$lastEventFullPath = Join-Path $lastEventFolder $lastEventFileName

$lastEventTimestamp = ""

# Check if the file exists
if (Test-Path $lastEventFullPath -PathType Leaf) {
    Write-Log "Found last events file: $lastEventFileName" INFO
    # Read the first line from the file
    $firstLine = Get-Content $lastEventFileName -First 1

    # Define a regex pattern for the timestamp format "2024-01-12T16:51:32.303Z"
    $timestampPattern = '^(?<Date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.)(?<Milliseconds>\d+)(?<Zone>Z)$'

    # Check if the first line matches the timestamp pattern
    if ($firstLine -match $timestampPattern) {
        # Assign the timestamp to a variable
        $lastEventTimestamp = $matches[0]

        # Display the timestamp
        Write-Log "Searching SET Admins events from $lastEventTimestamp" INFO
    } else {
        Write-Log "$firstLine does not match the expected timestamp format." ERROR
    }
} else {
    Write-Log "$($lastEventFileName): The file does not exist." WARN
}

if ([string]::IsNullOrWhiteSpace($lastEventTimestamp)) {
    $URLParm = "Limit=500"
} else {
    $URLParm = "DateFrom=$lastEventTimestamp"
}

$setAdminsAudits = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/AdminAudit?$URLParm" -Method 'GET' -Headers $sessionHeader

# Order events by EventTime
$setAdminsAuditsSortByEventTime = $setAdminsAudits.AdminAudits | Sort-Object -Property EventTime

# Write-Host "Searching for Audit Events..." -ForegroundColor DarkMagenta
Write-Log "Searching for Audit Events..." INFO
foreach ($setAdminsAudit in $setAdminsAuditsSortByEventTime) {
    if ($setAdminsAudit.PermissionDescription -eq "Create Policy" -or $setAdminsAudit.PermissionDescription -eq "Change Policy") {
        # Define Patter to clean up the policy name
        $pattern = '.*\"(.*?)\".*'
        if ($setAdminsAudit.Description -match $pattern) {
            $policyName = $Matches[1]
            Write-Log "$($setAdminsAudit.PermissionDescription) - $($setAdminsAudit.Feature): $policyName" INFO
            
        } else {
            Write-Log "No match found for $($setAdminsAudit.Description)." WARN
        }
    }

    # Update last event time
    $lastEventTime = $setAdminsAudit.EventTime
}

# Store $lastEventTime to the lastProcessedEvent.txt file
try {
    $lastEventTime | Set-Content -Path $lastEventFullPath -Encoding UTF8 -ErrorAction Stop
    Write-Log "Successfully wrote last event time to $lastEventFullPath" INFO
} catch {
    Write-Log "Error writing to $lastEventFullPath" ERROR
}

