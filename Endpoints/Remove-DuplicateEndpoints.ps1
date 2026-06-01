<#
.SYNOPSIS
    Analyzes a CSV report to identify and securely prune stale, duplicated endpoints from the EPM console.

.DESCRIPTION
    This script processes an EPM Endpoint Report to identify duplicate computer records
    and safely removes the obsolete entries via REST API.

    Execution Flows:
    1. Default Behavior: 
       Identifies duplicated hostnames from the CSV, queries the EPM API, and compares 
       the 'lastConnected' dates. It retains the single most recent connection and queues 
       all older duplicates for deletion.
       
    2. Strict Hardware Matching (-RemoveBySN): 
       Identifies duplicated hostnames from the CSV, queries the EPM API for duplicated hostnames
       but applies a secondary filter using the hardware Serial Number. Deletion only occurs if both
       the Hostname AND the Serial Number match. The oldest records in that specific hardware group are 
       deleted, while endpoints with unique Serial Numbers are safely preserved.

    Fail-Safes & Security:
    * Native '-WhatIf' and '-Confirm' support prevents accidental mass deletions.
    * If a record's 'lastConnected' date or ID is malformed/missing, it is safely 
      ignored and excluded from the deletion queue.
    * API deletion payloads are dynamically batched to respect HTTP constraints.    

.PARAMETER username
    The EPM username used for API authentication (e.g., user@domain).

.PARAMETER setName
    The specific name of the EPM set to query and modify.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER EndpointReportCSV
    Mandatory. The file path to the generated EPM Endpoint Report CSV.

.PARAMETER ForceDelete
    Switch. Whether to forcefully delete duplicate endpoints that currently have an 
    "Online" connection status. Disabled by default.

.PARAMETER RemoveBySN
    Switch. Restricts the deletion logic to endpoints that share both a duplicated 
    Hostname AND the exact same hardware Serial Number.

.PARAMETER ShowDebug
    Whetever or not show details info
    Disabled by default.

.EXAMPLE
    # EXAMPLE 1: The Security Best-Practice (Dry Run)
    .\Remove-DuplicateEndpoints.ps1 -EndpointReportCSV "C:\reports\endpoints.csv" -WhatIf
    
    # Executes the script in simulation mode. It parses the CSV, queries the API, and 
    # calculates the exact batching math, but outputs what *would* be deleted without 
    # actually sending the DELETE commands to the API.

.EXAMPLE
    # EXAMPLE 2: Strict Hardware Deletion
    .\Remove-DuplicateEndpoints.ps1 -EndpointReportCSV "report.csv" -RemoveBySN
    
    # Evaluates duplicates, but only deletes the older endpoints if the underlying 
    # hardware Serial Numbers perfectly match.

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 2
    Created: 09/2025
    Last Modified: 05/2026
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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

    [Parameter(Mandatory = $true, HelpMessage = "Endpoints Report")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$EndpointReportCSV,

    [Parameter(HelpMessage="Enable to check the SerialNumber")]
    [switch]$RemoveBySN = $false,
    
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

    $hErrorMsg = "API call failed at line $($MyInvocation.ScriptLineNumber)"

    while ($retryCount -lt $MaxRetries) {
        try {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
        }
        catch {
            $retryCount++
            $ErrorDetailsMessage = $null

            # Extract API error details if available
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try {
                    $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "$hErrorMsg - Failed to parse error message as JSON. Raw message: $($_.ErrorDetails.Message)" ERROR
                   # throw $_.ErrorDetails.Message
                }
            }

            # SCENARIO A: Network Failure (Connection closed, DNS, Timeout)
            if ($null -eq $ErrorDetailsMessage) {
                Write-Log "$hErrorMsg - $URI - HTTP Error: $($_.Exception.Message)" ERROR

                if ($_.Exception.Response) {
                    try {
                        $responseStream = $_.Exception.Response.GetResponseStream()
                        $reader = [System.IO.StreamReader]::new($responseStream)
                        $errorBody = $reader.ReadToEnd()
                        $reader.Close()

                        if (-not [string]::IsNullOrWhiteSpace($errorBody)) {
                            Write-Log "Server Error Detail: $errorBody" ERROR
                        }
                    } catch {
                        Write-Log "Stream unreadable (Connection severed)." ERROR
                    }
                }
                
                $TransientSleep = 5 * $retryCount # Exponential network backoff
                Write-Log "Retrying network connection ($retryCount/$MaxRetries) in $TransientSleep seconds..." WARN
                Start-Sleep -Seconds $TransientSleep
                continue # Jumps to the next iteration of the while loop

            }

            $EPMErrorCode = ""
            $EPMErrorMsg  = ""

            if ($null -ne $ErrorDetailsMessage) {
                # Use .PSObject.Properties to safely check if the property exists
                if ($ErrorDetailsMessage.PSObject.Properties.Match('ErrorCode').Count -gt 0) {
                    $EPMErrorCode = $ErrorDetailsMessage.ErrorCode
                }
                if ($ErrorDetailsMessage.PSObject.Properties.Match('ErrorMessage').Count -gt 0) {
                    $EPMErrorMsg = $ErrorDetailsMessage.ErrorMessage
                }
            }

            # Handle rate limit error (EPM00000AE)
            if ($EPMErrorCode -eq "EPM00000AE") {
                # Regex pattern to find numbers followed by "minute(s)"
                $pattern = "\d+\s+minute"
                $match = [regex]::Match($EPMErrorMsg, $pattern)
                if ($match.Success) {
                    $minutes = [int]($match.Value -replace '\s+minute', '')
                    [int]$RetryDelay = $minutes * 60
                    Write-Log "$EPMErrorMsg - Retrying in $RetryDelay seconds..." WARN
                } else {
                    Write-Log "$EPMErrorMsg - Retrying in $RetryDelay seconds (default)..." WARN
                }
                Start-Sleep -Seconds $RetryDelay
                continue
            }
                
            if ($EPMErrorCode -eq "EPM000002E" -and $null -ne $Body) {
                # Handle Body possible filter error 
                $MSG = "ErrorCode: $EPMErrorCode, ErrorMessage: $EPMErrorMsg"
                Write-Log "$hErrorMsg - $MSG" ERROR
                Write-Log "Please verify the filter body if present, as it could be the cause of this error code." ERROR
                throw $MSG
            }
            
            if ($EPMErrorCode -eq "EPM000012E") {
                # Handle Error EPM000012E - "ErrorMessage: EPM cannot identify the following target computers that were previously selected."
                Write-Log "$hErrorMsg - ErrorCode: $EPMErrorCode, ErrorMessage: $EPMErrorMsg" ERROR
                return
            }
            
            # Log any other error
            if ([string]::IsNullOrWhiteSpace($EPMErrorCode)) {
                $MSG = "Unhandled API Error: $($_.Exception.Message)"
            } else {
                $MSG = "ErrorCode: $EPMErrorCode, ErrorMessage: $EPMErrorMsg"
            }
            
            Write-Log "$hErrorMsg - $MSG" ERROR
            throw $MSG
        }
    }

    # If all retries fail, log and throw an error
    $MSG = "API call failed after $MaxRetries retries. URI: $URI"
    Write-Log $MSG ERROR
    throw $MSG
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

### Begin Script ###

$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

# Logging setup
$loggingEnabled = $Log.IsPresent -or $PSBoundParameters.ContainsKey('LogFolder')

if ($loggingEnabled) {
    
    if (-not $PSBoundParameters.ContainsKey('LogFolder')) {
        $logFolder = Join-Path $env:TEMP "$scriptName`_Logs"
    }

    if (-not (Test-Path -Path $logFolder -PathType Container)) {
        $null = New-Item -Path $logFolder -ItemType Directory -Force
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "$timestamp`_$scriptName.log"
    $logFilePath = Join-Path $logFolder $logFileName

    Write-Log -Message "Logging enabled. Log file: $logFilePath" -Level INFO
}

## Log file done

Write-Box "$scriptName"
##

# Connect to EPM
$credential = Get-Credential -UserName $username -Message "Enter password for $username"
$login = Connect-EPM -credential $credential -epmTenant $tenant
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
}
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName
Write-Box "$($set.setName)"

$URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"

Write-Log "Importing data from $EndpointReportCSV..." INFO

# Validate the CSV file
$RawHeaderString = Get-Content -LiteralPath $EndpointReportCSV -TotalCount 1
if ([string]::IsNullOrWhiteSpace($RawHeaderString)) {
    $ErrorMessage = "Schema Error: $EndpointReportCSV is completely empty."
    Write-Log $ErrorMessage ERROR
    throw $ErrorMessage
}

$RawHeader = $RawHeaderString -split ',' | ForEach-Object { $_.Trim('"') }
$RequiredHeaders = @('Computer', 'New Agent Id')

foreach ($Header in $RequiredHeaders) {
    if ($Header -notin $RawHeader) {
        $ErrorMessage = "Schema Error: Missing required column '$Header' in $EndpointReportCSV"
        Write-Log $ErrorMessage ERROR
        throw $ErrorMessage
    }
}

$NewAgentIdList = [System.Collections.Generic.HashSet[guid]]::new()
$NewAgentIdDuplicate = [System.Collections.Generic.HashSet[guid]]::new()

$HostnameList = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$HostnameDuplicate = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

# Scan the CSV to search duplicated hostname and duplpicated New Agent ID

foreach ($Row in (Import-Csv -LiteralPath $EndpointReportCSV)){
    $Hostname = $Row.Computer
    $NewAgentIDString = $Row.'New Agent Id'

    $NewAgentID = [guid]::Empty
    if ([guid]::TryParse($NewAgentIDString, [ref]$NewAgentID)) {
        if ($NewAgentID -ne [guid]::Empty) {    
            if (-not [string]::IsNullOrWhiteSpace($Hostname)) {
                if (-not $HostnameList.Add($Hostname)) {
                    [void]$HostnameDuplicate.Add($Hostname)
                }
            }

            if (-not $NewAgentIDList.Add($NewAgentId)) {
                [void]$NewAgentIdDuplicate.Add($NewAgentId)
            }
        }
    } else {
        Write-Log "Skipped row with invalid or missing New Agent ID for Hostname: $Hostname" ERROR
    }
}
        
Write-Log "Identified $($HostnameDuplicate.Count) Hostname duplicate of a total of $($HostnameList.Count) Hostname in $EndpointReportCSV" INFO
Write-Log "Identified $($NewAgentIdDuplicate.Count) New Agent ID duplicate of a total of $($NewAgentIdList.Count) New Agent ID in $EndpointReportCSV" INFO

if ($NewAgentIdDuplicate.Count -gt 0) {
    $JoinedDuplicates = $NewAgentIdDuplicate -join "`n"
    $ErrorMessage = "CRITICAL: Found Duplicated 'New Agent ID'(s). State corrupted. Please verify the following list and open a support case:`n$JoinedDuplicates"
    Write-Log $ErrorMessage ERROR
    throw $ErrorMessage
}

$RemoveIDs = [System.Collections.Generic.List[guid]]::new()

$counter = 0
$total = $HostnameDuplicate.Count

if ($RemoveBySN){
    # Search the duplicate in the console
    Write-Log "Checking Duplicate also by Serial Number" INFO
    
    foreach ($Hostname in $HostnameDuplicate) {
    
        $counter++
        Write-Log "$counter/$total - Processing $Hostname" INFO

        $FilterBody = @{
            "filter" = "name EQ $Hostname"
        } | ConvertTo-Json
            
        $EndpointsInventory = Invoke-EPMRestMethod -Uri "$URI/endpoints/inventory/Hardware" -Method 'POST' -Headers $sessionHeader -Body $FilterBody

        if (-not $EndpointsInventory) {
            Write-Log "$Hostname not found in EPM Console" WARN
            continue
        }

        if ($EndpointsInventory.Count -lt 2) {
            Write-Log "$Hostname retuned from the EPM Console is not duplicated" WARN
            continue
        }

        $EndpointsBySN = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::New([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($Endpoint in $EndpointsInventory) {
            $SN = $Endpoint.inventory.hardware.machineInfo.serialNumber

            if (-not $EndpointsBySN.ContainsKey($SN)) {
                $EndpointsBySN[$SN] = [System.Collections.Generic.List[psobject]]::new()
            }
            $EndpointsBySN[$SN].Add($Endpoint)
        }

        foreach ($SN in $EndpointsBySN.Keys) {
            $SNGroup = $EndpointsBySN[$SN]

            if ($SNGroup.Count -gt 1) {
                $sortedGroup = $SNGroup | Sort-Object { $_.lastConnected -as [datetime]} -Descending

                Write-Log "Endpoint to keep: $Hostname - New Agent ID: $($SortedGroup[0].id)" INFO

                for ($i = 1; $i -lt $SortedGroup.Count; $i++) {
                    [void]$RemoveIDs.Add($SortedGroup[$i].id)

                    Write-Log "Endpoint to remove: $Hostname - New Agent ID: $($SortedGroup[$i].id)" WARN
                }
            }
        }
    }
} else {
    
    Write-Log "Checking Duplicate." INFO
    
    foreach ($Hostname in $HostnameDuplicate) {
        
        $counter++
        Write-Log "$counter/$total - Processing $Hostname" INFO

        $FilterBody = @{
            "filter" = "name EQ $Hostname"
        } | ConvertTo-Json
            
        $EndpointsLive = Invoke-EPMRestMethod -Uri "$URI/Endpoints/search" -Method 'POST' -Headers $sessionHeader -Body $FilterBody

        if ($EndpointsLive.returnedCount -eq 0) {
            Write-Log "$Hostname not found in EPM Console" WARN
            continue
        }

        if ($EndpointsLive.returnedCount -lt 2) {
            Write-Log "$Hostname retuned from the EPM Console is not duplicated" WARN
            continue
        }

        if ($EndpointsLive.returnedCount -gt 1) {
            $sortedGroup = $EndpointsLive.endpoints | Sort-Object { $_.lastConnected -as [datetime]} -Descending
            Write-Log "Endpoint to keep: $Hostname - New Agent ID: $($SortedGroup[0].id)" INFO

            for ($i = 1; $i -lt $SortedGroup.Count; $i++) {
                [void]$RemoveIDs.Add($SortedGroup[$i].id)
                Write-Log "Endpoint to remove: $Hostname - New Agent ID: $($SortedGroup[$i].id)" WARN
            }
        }
    }
}

if ($RemoveIDs.Count -gt 0) {

    Write-Log "Preparing to delete $($RemoveIDs.Count) Endpoints" WARN

    # There is a limit to 10000 char for the filter string
    # (https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/delete-endpoint.htm#Bodyparameters)
    # Considering the following data:
    # GUID ID	36 characters
    # Separator (,)	1 character
    # Total per ID	37 characters
    # Prefix (id IN )	6 characters

    $MaxBatchSize = 250

    for ($i = 0; $i -lt $RemoveIDs.Count; $i += $MaxBatchSize) {

        $RemainingItems = $RemoveIDs.Count - $i
        $TakeCount = [Math]::Min($MaxBatchSize, $RemainingItems)
        $Batch = $RemoveIDs.GetRange($i, $TakeCount)        

        $FilterString = "id IN " + ($Batch -join ",")
            
        if ($PSCmdlet.ShouldProcess($FilterString, "DELETE Endpoints")) {

            $DeleteBody = @{
                "filter" = $FilterString
            }

            if ($ForceDelete) {
                $DeleteBody.force = $true
            }

            $DeleteBody = $DeleteBody | ConvertTo-Json -Compress

            $Result = Invoke-EPMRestMethod -Uri "$URI/Endpoints/delete" -Method 'POST' -Headers $sessionHeader -Body $DeleteBody

            if ($Result.statuses.psobject.Properties.Count -gt 0) {
                foreach ($property in $Result.statuses.psobject.Properties) {
                    if ($property.Name -eq "OK") {
                        Write-Log "Deleted: $($property.Value) - Status: $($property.Name)" INFO
                    } else {
                        Write-Log "Not Deleted: $($property.Value) - Status: $($property.Name)" WARN
                    }
                }
            } else {
                Write-Log "Not Deleted: $($Batch.Count) - Status: ID not presente or valid." WARN
            }
        }
    }
} else {
    Write-Log "No Duplicated Endpoints" INFO
}