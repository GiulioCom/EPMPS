<#
.SYNOPSIS
    Remove-EPMEndpoints - Removes Endpoints via EPM REST API using a CSV report.

.DESCRIPTION
    This script reads a CSV export from CyberArk EPM, filters out "Zero GUIDs," and batches 
    Agent IDs to perform a bulk deletion. It respects the 10,000 character API limit 
    by slicing data into batches of 250. 
    
    Note: This script targets 'New Agent IDs' and does not support 'MyComputer' objects.

.PARAMETER username
    The EPM username used for authentication (e.g., admin@cyberark.com).

.PARAMETER setName
    The specific EPM Set Name where the endpoints reside.

.PARAMETER tenant
    The EPM tenant/region prefix (e.g., 'eu', 'na', 'uk').

.PARAMETER EndpointReportCSV
    The full path to the CSV report containing the 'New Agent Id' and 'Computer' columns.

.PARAMETER ForceDelete
    If specified, forces the deletion of endpoints even if their status is "Online".

.PARAMETER ShowDebug
    If specified, enables detailed DEBUG logging for troubleshooting API payloads and responses.

.EXAMPLE
    - .\Remove-EPMEndpoints -username "admin@corp" -setName "Workstations" -tenant "eu" -EndpointReportCSV "C:\Reports\Duplicates.csv" -WhatIf
      Runs a simulation showing which batches would be sent to the API without executing the deletion.
    - .\Remove-EPMEndpoints -username "admin@corp" -setName "Workstations" -tenant "eu" -EndpointReportCSV "C:\Reports\Duplicates.csv" -Confirm
      Request for confirmation for each batch before execute the deletion
    - .\Remove-EPMEndpoints -username "admin@corp" -setName "Workstations" -tenant "eu" -EndpointReportCSV "C:\Reports\Duplicates.csv"
      Remove Endponits without asking for confirmation
.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 02/2026
#>    

[CmdletBinding(SupportsShouldProcess = $true)]
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
    [string]$logFolder,

    [Parameter(Mandatory = $true, HelpMessage = "Endpoints Report")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$EndpointReportCSV,

    [Parameter(HelpMessage="Force delete the endpoint from this list, even if the endpoint is currently connected.")]
    [switch]$ForceDelete,

    [switch]$ShowDebug = $false
)

## Write-Host Wrapper and log management
function Write-Log {
    <#
    .SYNOPSIS
        Outputs a formatted log message to the console and a file.
    #>
    param (
        [Parameter(Mandatory = $true)] [string]$message,
        [Parameter(Mandatory = $true)] [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")] [string]$severity,
        [ConsoleColor]$ForegroundColor
    )

    if ($severity -eq "DEBUG" -and -not $ShowDebug) { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$($severity.PadRight(5))] $message"

    if (-not $PSBoundParameters.ContainsKey('ForegroundColor')) {
        $ForegroundColor = switch ($Severity) {
            "INFO"  { "Green" }
            "WARN"  { "Yellow" }
            "ERROR" { "Red" }
            "DEBUG" { "Gray" }
        }
    }

    Write-Host $logMessage -ForegroundColor $ForegroundColor

    if ($log) {
        Add-Content -Path $LogPath -Value $logMessage
    }
}

function Write-Box {
    <#
    .SYNOPSIS
        Displays a centered title within a fixed 42-character decorative box.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({$_.Length -le 38})]
        [string]$title
    )

    $totalWidth = 42
    $contentWidth = $totalWidth - 2
    
    # Calculate padding for centering
    $leftPadding  = [Math]::Floor(($contentWidth - $title.Length) / 2)
    $rightPadding = $contentWidth - $title.Length - $leftPadding
    
    # Construct lines
    $horizontalLine = "+" + ("-" * ($totalWidth - 2)) + "+"
    $centeredText   = "|" + (" " * $leftPadding) + $title + (" " * $rightPadding) + "|"

    $textProp = @{
        "Severity"        = "INFO"
        "ForegroundColor" = "Cyan"
    }
    
    $textProp = @{
        "Severity" = "INFO"
        "ForegroundColor" = "Cyan"
    }

    Write-Log $horizontalLine @textProp
    Write-Log $centeredText   @textProp
    Write-Log $horizontalLine @textProp
}

## Invoke-RestMethod Wrapper
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
        [int]$RetryDelay = 120 # Default value, in case of the returned message doesn't contain the limit info
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
                    Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds..." WARN
                }

                Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds (default)..." WARN
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

function Get-EPMSetID {
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

    Write-Box "Available Sets:"

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

function Remove-EPMEndpointBatch {
    <#
    .SYNOPSIS
        Removes EPM endpoints in batches, respecting API character limits.
    
    .DESCRIPTION
        Processes an array of Agent IDs and performs a bulk deletion via the EPM REST API.
        The function batches IDs to respect the 10,000 character limit for the filter string.
        Documentation: https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/delete-endpoint.htm#Bodyparameters
    
    .PARAMETER IdList
        An array of strings containing the 'New Agent Id' GUIDs.
    .PARAMETER BaseUri
        The base URL of the EPM Manager (e.g., https://na123.epm.cyberark.com).
    .PARAMETER SetId
        The Unique ID of the EPM Set.
    .PARAMETER SessionHeader
        The hashtable containing the Authorization header/token.
    .PARAMETER Force
        If switch is present, adds the 'force' parameter to the API body.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$IdList,

        [Parameter(Mandatory = $true)]
        [string]$BaseUri,

        [Parameter(Mandatory = $true)]
        [hashtable]$SessionHeader
    )

    process {
        # --- API Constraints Documentation & Logic ---
        # Limit: 10,000 characters for the filter string.
        # Prefix: "id IN " = 6 chars.
        # GUID (36) + Comma (1) = 37 chars. 
        # (10,000 - 6) / 37 = 270 max. 250 is a safe, efficient buffer.
        $MaxCharLimit = 10000
        $MaxBatchSize = 250
        $TotalCount   = $IdList.Count

        Write-Log "Starting batch deletion for $TotalCount endpoints (Batch Size: $MaxBatchSize)." INFO
        Write-Log "Remove Connnected Endpoint: $([bool]$ForceDelete)" WARN

        for ($i = 0; $i -lt $TotalCount; $i += $MaxBatchSize) {
            
            $Remaining = $TotalCount - $i
            $CurrentBatchSize = [Math]::Min($MaxBatchSize, $Remaining)
            
            $Batch = [string[]]::new($CurrentBatchSize)
            [Array]::Copy($IdList, $i, $Batch, 0, $CurrentBatchSize)

            $FilterString = "id IN " + ($Batch -join ",")

            if ($FilterString.Length -gt $MaxCharLimit) {
                Write-Log "Safety Error: Filter string length ($($FilterString.Length)) exceeds limit. Skipping index $i." ERROR
                continue
            }

            $Body = @{ 
                "filter" = $FilterString
                "force" = [bool]$ForceDelete 
            }

            $RemoveEndpointsParam = @{
                Uri = "$BaseUri/Endpoints/delete"
                Method = 'POST' 
                Headers = $SessionHeader
                Body = $Body | ConvertTo-Json
            }

            # Execute with ShouldProcess (WhatIf support)
            $ActionMessage = "Deleting batch of $CurrentBatchSize endpoints starting at index $i"
            Write-Log $ActionMessage INFO
            if ($PSCmdlet.ShouldProcess($ActionMessage)) {
                try {
                    $Result = Invoke-EPMRestMethod @RemoveEndpointsParam

                    if ($Result.statuses.psobject.Properties.Count -gt 0) {
                        foreach ($prop in $Result.statuses.psobject.Properties) {
                            $LogLevel = if ($prop.Name -eq "OK") { "INFO" } else { "WARN" }
                            Write-Log "Batch Result - Status: $($prop.Name), Count: $($prop.Value)" $LogLevel
                        }
                    } else {
                        Write-Log "No Endpoints founds to be deleted." WARN
                    }
                }
                catch {
                    Write-Log "Request failed for batch at index $i. Error: $($_.Exception.Message)" ERROR
                }
            }
        }
    }
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
##

Write-Box "$scriptName"
##

# Validate CSV
$RequiredHeaders = @('Agent Id', 'Computer', 'Last Seen','New Agent Id')
#$HeaderRow = Get-Content -Path $EndpointReportCSV -TotalCount 1 | ConvertFrom-Csv
$HeaderRow = Import-Csv -Path $EndpointReportCSV | Select-Object -First 1
foreach ($Header in $RequiredHeaders) {
    if ($null -eq $HeaderRow.$Header) {
        $ErrorMessage = "Security/Schema Error: Missing required column '$Header' in $EndpointReportCSV"
        Write-Log $ErrorMessage ERROR
        Throw $ErrorMessage
    }
}

Write-Log "Importing data from $EndpointReportCSV..." INFO
$IdList = Import-Csv -Path $EndpointReportCSV | ForEach-Object {    
    $NewAgentId = $_.'New Agent Id'
    if ([string]::IsNullOrWhiteSpace($NewAgentId) -or $NewAgentId -eq "00000000-0000-0000-0000-000000000000") {
        Write-Log "Agent not compatible with script. New Agent ID missing." WARN
        Write-Log "Row: $(($_.psobject.Properties.Value) -join ',')" WARN
    } else {
        Write-Log "Added to the deletion list: $_" DEBUG
        Write-Log "Row: $(($_.psobject.Properties.Value) -join ',')" DEBUG
        $NewAgentId
    }
}

if ($null -eq $IdList) {
    Write-Log "No valid Agent IDs found to process. Exiting." WARN
    return
}

Write-Log "Collected $($IdList.Count) for deletion." INFO

# Connect to EPM
$credential = Get-Credential -UserName $username -Message "Enter password for $username"
$login = Connect-EPM -credential $credential -epmTenant $tenant
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
}
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName
Write-Box "$($set.setName)"

$RemoveEPMEndpointBatchParam = @{
    IdList = $IdList
    BaseUri = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"
    SessionHeader = $sessionHeader
}
Remove-EPMEndpointBatch @RemoveEPMEndpointBatchParam




<#

# There is a limit to 10000 char for the filter string
# (https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/delete-endpoint.htm#Bodyparameters)
# Considering the following data:
# GUID ID	36 characters
# Separator (,)	1 character
# Total per ID	37 characters
# Prefix (id IN )	6 characters

$MaxBatchSize = 250

for ($i = 0; $i -lt $IdList.Count; $i += $MaxBatchSize) {

    $Batch = $IdList[$i..($i + $MaxBatchSize - 1)]

    if (-not $Batch) {
        Write-Log "Error: Failed to slice batch starting at index $i. Skipping." ERROR
        continue
    }

    $FilterString = "id IN " + ($Batch -join ",")

    if ($FilterString.Length -gt 10000) {
        Write-Log "FATAL ERROR: Calculated filter string length ($($FilterString.Length)) exceeded 10000 chars. ABORTING BATCH." ERROR
        continue
    }

    $DeleteBody = @{ "filter" = $FilterString }
    if ($ForceDelete) { $DeleteBody.force = $true }
    $DeleteBody = $DeleteBody | ConvertTo-Json

    $Result = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/delete" -Method 'POST' -Headers $sessionHeader -Body $DeleteBody

    if ($Result.statuses.psobject.Properties.Count -gt 0) {
        foreach ($property in $Result.statuses.psobject.Properties) {
            if ($property.Name -eq "OK") {
                Write-Log "Deleted: $($property.Value) - Status: $($property.Name)" INFO
            } else {
                Write-Log "Not Deleted: $($property.Value) - Status: $($property.Name)" WARN
            }
        }
    } else { Write-Log "Not Deleted: $($Batch.Count) - Status: ID not presente or valid." WARN }
}
#>