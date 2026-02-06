<#
.SYNOPSIS
    Remove Duplciated Endpoints by readind the Endpoints Report

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER EndpointReportCSV
    Mandatory: Report file

.PARAMETER delete
    Whetever or not running the deletion of duplicates.
    Disabled By default.

.PARAMETER ForceDelete
    Whetever or not force deletion of endpoint having status "Online".
    Disabled by default.

.PARAMETER ShowDebug
    Whetever or not show details info
    Disabled by default.

.NOTES
    File: EPMDuplicateEndpointsFromFile.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 2
    Created: 09/2025
    Last Modified: 02/2026
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(Mandatory = $true, HelpMessage="Endpoints Report")]
    [string]$EndpointReportCSV,

    [Parameter(HelpMessage="Delete duplicated Endpoint")]
    [switch]$delete = $false,

    [Parameter(HelpMessage="Force delete the endpoint from this list, even if the endpoint is currently connected.")]
    [switch]$ForceDelete = $false,

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

if (-not $delete){ Write-Log "Analysis Mode Enabled." INFO DarkGreen}
else { Write-Log "Delete Mode Enabled." INFO DarkGreen}

Write-Log "Importing data from $EndpointReportCSV..." INFO
$EndpointstotalCount = (Get-Content $EndpointReportCSV | Measure-Object).Count - 1

Write-Log "Searching for duplicated..." INFO

$DuplicatedEndpoints = [System.Collections.Generic.List[Object]]::new()
$LatestEndpoints = @{} # Key = Computer Name (Endpoint.name), Value = Endpoint Object

$processedEndpoints = 0
$updateInterval = [Math]::Max(1, [Math]::Floor($EndpointsTotalCount / 100)) # Update every 1%

Import-Csv -Path $EndpointReportCSV | ForEach-Object {    

    if ($processedEndpoints % $updateInterval -eq 0) {
        $Percent = (($processedEndpoints / $EndpointstotalCount) * 100)
        Write-Progress -Activity "Processing Endpoints $EndpointsTotalCount" -Status "Processed: $processedEndpoints Endpoints" -PercentComplete $Percent
    }
    
    $LastSeenDate = $_."Last Seen" -as [DateTime]
    if (-not $LastSeenDate) { $LastSeenDate = [DateTime]::MinValue }
    
    $CurrentEndpoint = [PSCustomObject]@{
        Computer     = $_.Computer
        NewAgentId   = $_."New Agent Id"
        AgentVersion = $_."Agent Version"
        _ParsedDate  = $LastSeenDate
    }

    if ($LatestEndpoints.ContainsKey($CurrentEndpoint.Computer)) {
        $ExistingEndpoint = $LatestEndpoints[$CurrentEndpoint.Computer]
        
        if ($CurrentEndpoint._ParsedDate -gt $ExistingEndpoint._ParsedDate) {
            $DuplicatedEndpoints.Add($ExistingEndpoint)
            $LatestEndpoints[$CurrentEndpoint.Computer] = $CurrentEndpoint
        } else { $DuplicatedEndpoints.Add($CurrentEndpoint) }
    }
    else { $LatestEndpoints[$CurrentEndpoint.Computer] = $CurrentEndpoint }
    $processedEndpoints++
}

Write-Progress -Activity "Processing Endpoints $($EndpointsTotalCount)" -Status "Completed: $processedEndpoints Endpoints" -PercentComplete 100 -Completed

Write-Log "Identified $($DuplicatedEndpoints.Count) duplicated endpoints to remove." INFO

$IdList = foreach ($Dup in $DuplicatedEndpoints) {
    $EndpointInfoMessage = "$($Dup.Computer) - ID: $($Dup.NewAgentId) (LastSeen: $($Dup._ParsedDate), Version: $($Dup.AgentVersion))"

    if ($Dup.NewAgentId -eq "00000000-0000-0000-0000-000000000000") {
        Write-Log "Agent not compatible with script. Use MyComputer instead: $EndpointInfoMessage" WARN
    } else {
        Write-Log "To be deleted (batch): $EndpointInfoMessage" DEBUG
        $Dup.NewAgentId
    }
}

Write-Log "Identified $($IdList.Count) duplicated endpoints to remove." INFO

if ($delete){
    if ($IdList.Count -gt 0) {

        # Connect to EPM
        $credential = Get-Credential -UserName $username -Message "Enter password for $username"
        $login = Connect-EPM -credential $credential -epmTenant $tenant
        $sessionHeader = @{
            "Authorization" = "basic $($login.auth)"
        }
        $set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName
        Write-Box "$($set.setName)"        
        
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
    
            #Write-Log "Processing batch starting with ID $($Batch[0]) (Count: $($Batch.Count), Length: $($FilterString.Length))." INFO
    
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
    } else { Write-Log "No Duplicated Endpoints" WARN }
} else { Write-Log "Demo Mode - No deletion" WARN }