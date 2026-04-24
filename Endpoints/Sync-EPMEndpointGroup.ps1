<#
.SYNOPSIS
    Sync computer group by reading a CSV file.

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER policyFile
    The full path to the input CSV file. The file must contain two columns:
        1. The Computer Name (e.g., WIN10X64-1).
        2. A semicolon-separated list of EPM Groups (e.g., EarlyAdopter;PreProd).
    
    Example CSV format:
    WIN10X64-1,EarlyAdopter;PreProd
    WIN11-1,PreProd

.EXAMPLE
    .\Sync-EPMEndpointGroup.ps1 -username "admin@epm.com" -setName "Default Set" -tenant "eu" -MappingCsvPath "C:\temp\policy_assignments.csv"

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 11/2025

    Update: 04/2026
    - Using the "Add or update static group members by filter" API: https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-group-apis/add-or-update-static-group-members-by-filter.htm

#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$Username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$SetName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch", "beta")]
    [string]$Tenant,

    [Parameter(Mandatory = $true, HelpMessage="Path to the Mapping CSV (EndpointName, GroupName)")]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) { 
            throw "Path '$_' must be a valid file. Folders are not supported." 
        }
        $true
    })]
    [string]$MappingCsvPath,

#    [Parameter(Mandatory = $false, HelpMessage="Optional: EPM Endpoints Report for ID lookups")]
#    [ValidateScript({
#        if (-not (Test-Path $_ -PathType Leaf)) { 
#            throw "Path '$_' must be a valid file. Folders are not supported." 
#        }
#        $true
#    })]
#    [string]$LookupCsvPath,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$Log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$LogFolder,

    [Parameter(HelpMessage = "Enable Debug log")]
    [switch]$ShowDebug

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
        Add-Content -Path $logFilePath -Value $logMessage
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
        "Severity" = "INFO"
        "ForegroundColor" = "Cyan"
    }

    Write-Log $horizontalLine @textProp
    Write-Log $centeredText   @textProp
    Write-Log $horizontalLine @textProp
}
##

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

            if ($null -eq $ErrorDetailsMessage) {
                $GenericError = "$URI - HTTP Error: $($_.Exception.Message)"
                Write-Log $GenericError ERROR
                throw $GenericError
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
                } else {
                    Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds (default)..." WARN
                }
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } else {
                
                if ($ErrorDetailsMessage.ErrorCode -eq "EPM000002E" -and $null -ne $Body) {
                # Handle Body possible filter error 
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    Write-Log "Please verify the filter body if present, as it could be the cause of this error code." ERROR
                    throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                } elseif ($ErrorDetailsMessage.ErrorCode -eq "EPM000012E") {
                # Handle Error EPM000012E - "ErrorMessage: EPM cannot identify the following target computers that were previously selected."
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    return
                }
                else {
                # Log any other error
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
        $message = "Failed to retrieve EPM Sets. Error: $_" 
        Write-Log $message ERROR
        throw $message
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

Function Get-EPMEndpoints {
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
    param (
        [int]$limit = 1000,     #Set limit to the max size if not declared
        [hashtable]$filter      #Set the search body
    )

    $mergeEndpoints = [PSCustomObject]@{
        endpoints = @()
        filteredCount = 0
        returnedCount = 0
    }

    if ($null -ne $filter) {
        $filterJSON = $filter | ConvertTo-Json
    }

    $offset = 0             # Offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        $getEndpoints = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/search?offset=$offset&limit=$limit" -Method 'POST' -Headers $sessionHeader -Body $filterJSON
        
        $mergeEndpoints.endpoints += $getEndpoints.endpoints    # Merge the current computer list
        $mergeEndpoints.filteredCount = $getEndpoints.filteredCount   # Update the filteredCount (the total device based on the filter)
        $mergeEndpoints.returnedCount = $getEndpoints.returnedCount   # Update the returnedCount

        $total = $getEndpoints.filteredCount   # Update the total with the real total
        $offset += $getEndpoints.returnedCount

        # Progress Bar
        Write-Progress -Activity "Retrieving Endpoints $($total) total" -Status "Retrieved: $offset Endpoints" -PercentComplete $Percent
    }
    Write-Progress -Activity "Retrieving Endpoints $($total) total"  -Status "Completed: Successfully retrieved $($mergeEndpoints.filteredCount) Endpoints" -PercentComplete 100 -Completed
    
    return $mergeEndpoints
}

## Script Functions
function ConvertTo-EpmGroupData {
<#
.SYNOPSIS
    Converts a CSV file of computer-to-group mappings into
    PowerShell objects, one per group, with a list of associated computers.

.DESCRIPTION
    Reads a two-column, header-less CSV file.
    Column 1: ComputerName
    Column 2: Semicolon-separated list of EPM groups

.PARAMETER Path
    The full path to the input CSV file.

.PARAMETER GroupLookup
     A pre-built hash table that maps [GroupName] to [GroupID].
    If provided, the GroupId property will be populated.
    If a group from the CSV is not found in this map, GroupId will be $null.

.OUTPUTS
    [PSCustomObject]
    Streams objects to the pipeline, each with:
    - roupName (string)
    - GroupId (always $null, as a placeholder)
    - Endpoints (array of strings)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if (-not (Test-Path -Path $_ -PathType Leaf)) {
                throw "File not found: $_"
            }
            return $true
        })]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [System.Collections.IDictionary]$GroupLookup
    )

    Write-Log "Starting EPM Group processing for file: $Path" INFO

    $groupMap = @{}

    $headers = 'ComputerName', 'GroupList'
    $csvStream = Import-Csv -Path $Path -Header $headers

    foreach ($row in $csvStream) {
        # Forcing uppercase
        $computer = $row.ComputerName.ToUpper().Trim()
        if ([string]::IsNullOrWhiteSpace($computer)) {
            Write-Log "Skipping row with empty computer name." WARN
            continue
        }
        if ([string]::IsNullOrWhiteSpace($row.GroupList)) {
            Write-Log "Skipping computer '$computer': no groups listed." WARN
            continue
        }

        # Split the group list string into an array
        $groups = $row.GroupList -split ';'

        foreach ($group in $groups) {
            $trimmedGroup = $group.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmedGroup)) {
                # Check if group exists
                if (-not $groupMap.ContainsKey($trimmedGroup)) {
                    # If not, create a new *List* for it.
                    $groupMap[$trimmedGroup] = [System.Collections.Generic.List[string]]::new()
                }
                
                # Add the computer to this group's list
                $groupMap[$trimmedGroup].Add($computer)
            }
        }
    }

    Write-Log "Grouping complete. Found $($groupMap.Keys.Count) groups." INFO

    foreach ($entry in $groupMap.GetEnumerator()) {
        
        $groupId = $null
        if ($null -ne $GroupLookup -and $GroupLookup.ContainsKey($entry.Key)) {
            $groupId = $GroupLookup[$entry.Key]
        }        
        
        # This object is written to the output stream
        [PSCustomObject]@{
            GroupName = $entry.Key
            GroupId      = $groupId
            Endpoints    = $entry.Value # This is the [List[string]] containig the list of Endpoints 
        }
    }
}

function Invoke-EPMMemberUpload {
    param($Endpoints, $GroupId, $Override)

    if ($Endpoints.Count -eq 1) {
        $FilterString = "name EQ '$($Endpoints[0])'"
    } else {
        #$FilterString = "name IN '$($Endpoints -join "','")'"
        $FilterString = 'name IN "{0}"' -f ($Endpoints -join '","')
    }

    Write-Log "$FilterString" DEBUG
    
    $UpdateGroupBody = @{
        "filter"   = $FilterString
        "override" = [bool]$Override
    } | ConvertTo-Json -Compress

    $addMembers = Invoke-EPMRestMethod -Uri "$URI/Endpoints/Groups/$GroupId/members" -Method 'POST' -Headers $sessionHeader -Body $UpdateGroupBody
    
    if ($addMembers.count -ge $Endpoints.Count) {
        Write-Log "Successfully uploaded: $($addMembers.count)/$($Endpoints.Count) members." INFO
    } elseif ($addMembers.count -lt $Endpoints.Count) {
        Write-Log "Successfully uploaded: $($addMembers.count)/$($Endpoints.Count) members." WARN
    } else {
        Write-Log "API responded but no members were updated for Group $GroupId." WARN
    }
}

### Begin Script ###

$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

## Prepare log folder and file
# Set default log folder if not provided
if ($log) {
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
    $logFileName = "$timestamp`_$scriptName.log"
    $logFilePath = Join-Path $logFolder $logFileName

    Write-Log "Logging enabled. Log file: $logFilePath" INFO
}
##

Write-Box "$scriptName"

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

# Define common URI
$URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

# Get Static Groups
$compGroupFilter = @{
    "filter" = "type EQ Static"
} | ConvertTo-Json
$getEndpointGroups = Invoke-EPMRestMethod -Uri "$URI/Endpoints/groups/search" -Method 'POST' -Headers $sessionHeader -Body $compGroupFilter

$EndpointsGroupMap = @{} # Map of [GroupName] = GroupID
foreach ($group in $getEndpointGroups) {
    $EndpointsGroupMap[$group.name] = $group.id
}

# Adding by computer name:
# https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-group-apis/add-or-update-static-group-members-by-filter.htm

ConvertTo-EpmGroupData -Path $MappingCsvPath -GroupLookup $EndpointsGroupMap | ForEach-Object {
    Write-Log "Processing Group: $($_.GroupName)..." INFO
    
    if ($null -eq $_.GroupId) {
        Write-Log "Group '$($_.GroupName)' does not exist. Creating..." INFO
       
        $GroupPayload = @{
            "type" = "Static"
            "name" = $($_.GroupName)
            "description" = "Created by script"
        } | ConvertTo-Json
        
        $addGroup = Invoke-EPMRestMethod -Uri "$URI/Endpoints/Groups" -Method 'POST' -Headers $sessionHeader -Body $GroupPayload
        if ($null -eq $addGroup -or -not $addGroup.id) {
            Write-Log "Group creation for '$($_.GroupName)' failed. API returned no ID." ERROR
            continue
        }
        Write-Log "Group '$($_.GroupName)' created successfully with ID: $($addGroup.id)." INFO
        $GroupID = $addGroup.id
    } else {
        Write-Log "Group '$($_.GroupName)' (ID: $($_.GroupId)) exists." INFO
        $GroupID = $_.GroupId
    }
    
    Write-Log "Adding $($_.Endpoints.Count) members to '$($_.GroupName)'." INFO

    # Managing the filter lenght limitation = 5120
    
    $CurrentBatch = [System.Collections.Generic.List[string]]::new()
    $CurrentLength = 10 # Starting overhead for "name IN ()"
    $IsFirstBatch = $true
    $TotalProcessedCount = 0
    $BatchNumber = 0
    
    foreach ($Endpoint in $_.Endpoints) {
        $EntryLength = $Endpoint.Length + 3 # for each Endpoint single quote and comma: '',
    
        if (($CurrentLength + $EntryLength) -gt 5100) {
            $BatchNumber++
            Write-Log "Processing Batch $BatchNumber ($($CurrentBatch.Count) items). Overall: $TotalProcessedCount/$($_.Endpoints.Count)" INFO
            Invoke-EPMMemberUpload -Endpoints $CurrentBatch -GroupId $GroupID -Override $IsFirstBatch
        
            $IsFirstBatch = $false
            $CurrentBatch.Clear()
            $CurrentLength = 10
        }

        $CurrentBatch.Add($Endpoint)
        $CurrentLength += $EntryLength
        $TotalProcessedCount++
    }

    if ($CurrentBatch.Count -gt 0) {
        if ($BatchNumber -gt 0) {
            $BatchNumber++
            Write-Log "Processing Batch $BatchNumber ($($CurrentBatch.Count) items). Overall: $TotalProcessedCount/$($_.Endpoints.Count)" INFO
        } else {
            Write-Log "Processing $($_.Endpoints.Count)." INFO
        }
        Invoke-EPMMemberUpload -Endpoints $CurrentBatch -GroupId $GroupID -Override $IsFirstBatch
    }    
    
    <#
    $EndpointsList = $_.Endpoints -join ','
    Write-Log "Endpoints: $EndpointsList" INFO

    if ($_.Endpoints.Count -eq 1) {
        $filter = "name EQ $EndpointsList"
    } else {
        $filter = "name IN $EndpointsList"
    }

    $UpdateGroupBody = @{
        "filter" = $filter
        "override" = $true
    } | ConvertTo-Json
    
    $addMembers = Invoke-EPMRestMethod -Uri "$URI/Endpoints/Groups/$GroupID/members" -Method 'POST' -Headers $sessionHeader -Body $UpdateGroupBody

    if ($addMembers.count -ge $_.Endpoints.Count) {
        Write-Log "Successfully added $($addMembers.Count) members in '$($_.GroupName)'." INFO    
    } elseif ($addMembers.count -lt $_.Endpoints.Count){
        Write-Log "Only $($addMembers.count) of $($_.Endpoints.Count) uploaded." WARN
    } else {
        Write-Log "Error uploading..." ERROR
    }
    #>
}


<#
# Get Endpoints
## Initialize a Hashtable to store ComputerName as the Key
## and an ArrayList of IDs.
## If there are more value for the same Endpoint name (duplicated)
## The ID will be added to the same ComputerName

$EndpointLookup = @{}

# Adding Map logic
$AddInfoToMap = {
    param($CompName, $AgentId)
    $CleanName = $CompName.Trim()
    $CleanId = [string]$AgentId.Trim()

    if (-not [string]::IsNullOrWhiteSpace($CleanName)) {
        if (-not $EndpointLookup.ContainsKey($CleanName)) {
            $EndpointLookup[$CleanName] = [System.Collections.Generic.List[string]]::new()
        }
        $EndpointLookup[$CleanName].Add($CleanId)
    }
}

if ($null -ne $LookupCsvPath) {

    Write-Log "Importing data from $LookupCsvPath..." INFO

    # Validate CSV
    $HeaderChecked = $false
    Import-Csv -Path $LookupCsvPath | ForEach-Object {
        if (-not $HeaderChecked) {
            $RawHeaders = $_.psobject.properties.name
                if ('Computer' -notin $RawHeaders -or 'New Agent Id' -notin $RawHeaders) {
                    throw "Schema Error: Missing required columns in $LookupCsvPath"
                }
            $HeaderChecked = $true
        }
        &$AddInfoToMap -CompName $_.Computer -AgentId $_.'New Agent Id'
    }
} else {

    Write-Log "WARNING: No Endpoints Report (LookupCsvPath) was provided." WARN
    Write-Log "- The script will query the EPM Console directly." WARN
    Write-Log "- RISK: This may hit the 100,000 daily API request limit." WARN
    Write-Log "- ADVICE: For large-scale operations, use a CSV report to save API quota." WARN
    $Confirmation = Read-Host "Are you sure you want to continue with direct API access? (y/N)"

    if ($Confirmation -ne 'y') {
        Write-Log "Operation cancelled by user to preserve API quota." INFO
        return
    }

    $getEndpoints = Get-EPMEndpoints

    foreach ($endpoint in $getEndpoints.endpoints) {
        &$AddInfoToMap -CompName $_.Computer -AgentId $_.'New Agent Id'
    }
}

#>

<#
ConvertTo-EpmGroupData -Path $source -GroupLookup $EndpointsGroupMap | ForEach-Object {
    
    Write-Log "Processing Group: $($_.GroupName)..." INFO
    Write-Log "  Computers: ($($_.Endpoints -join ', '))" DEBUG

    # Convert ComputerName to Computer ID
    $memberIDsList = [System.Collections.Generic.List[string]]::new()
    foreach ($Endpoint in $_.Endpoints) {
        if ($EndpointLookup.ContainsKey($Endpoint)) {
            $memberIDsList.AddRange($EndpointLookup[$Endpoint])

        } else {
            Write-Log "Endpoint '$computerName' not found in EPM inventory. Skipping for group '$($_.GroupName)'." WARN
        }
    }
    
    # Check if we have any valid IDs left to process
    if ($memberIDsList.Count -eq 0) {
        Write-Log "Skipping group '$($_.GroupName)': No members found in EPM inventory." WARN
        return # Skip to the next group
    }

    # Prepare Body for Update Group
    $memberIDs = @{
        "membersIds" = $memberIDsList
    } | ConvertTo-Json
    
    if ($null -eq $_.GroupId) {
        # Group missing - Create New Group
        Write-Log -Message "Group '$($GroupObject.EpmGroupName)' does not exist. Creating..." INFO
       
        $compGroupAdd = @{
            "type" = "Static"
            "name" = $($GroupObject.EpmGroupName)
            "description" = "Created by script"
        } | ConvertTo-Json
        
        $createCompGroups = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/Groups" -Method 'POST' -Headers $sessionHeader -Body $compGroupAdd
        if ($null -eq $createCompGroups -or -not $createCompGroups.id) {
            Write-Log "Group creation for '$($_.EpmGroupName)' failed. API returned no ID." ERROR
            continue
        }
        Write-Log "Group '$($GroupObject.EpmGroupName)' created successfully with ID: $($createCompGroups.id)." INFO
        
        $addMembersIDs = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/Groups/$($createCompGroups.id)/members/ids" -Method 'POST' -Headers $sessionHeader -Body $memberIDs
        Write-Log "Successfully added $($addMembersIDs.Count) members to new group '$($GroupObject.EpmGroupName)'." INFO    
    }
    else {
        # Group present
        Write-Log "Group '$($_.EpmGroupName)' (ID: $($_.GroupId)) exists. Updating members..." INFO
        $addMembersIDs = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/Groups/$($GroupObject.GroupId)/members/ids" -Method 'POST' -Headers $sessionHeader -Body $memberIDs
        Write-Log "Successfully added $($addMembersIDs.Count) members to new group '$($GroupObject.EpmGroupName)'." INFO    
    }
}
#>