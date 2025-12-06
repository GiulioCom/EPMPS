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
    .\EPMsyncComputerGroup.ps1 -username "admin@epm.com" -setName "Default Set" -tenant "eu" -source "C:\temp\policy_assignments.csv"

.NOTES
    File: EPMAddComputertoPolicy.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 11/2025

    TODO: the script only add computer in group or ADD new group. Future release the script will remove computer from group or remove groups and fullt sync the CSV fileprocessed
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch", "beta")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(Mandatory=$true)]
    [string]$source
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
Function Get-EPMEndpoints {
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
    $iteration = 1          # Define the number of iteraction, used to increase the offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        $getEndpoints = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/search?offset=$offset&limit=$limit" -Method 'POST' -Headers $sessionHeader -Body $filterJSON
        
        $mergeEndpoints.endpoints += $getEndpoints.endpoints    # Merge the current computer list
        $mergeEndpoints.filteredCount = $getEndpoints.filteredCount   # Update the filteredCount (the total device based on the filter)
        $mergeEndpoints.returnedCount = $getEndpoints.returnedCount   # Update the returnedCount

        $total = $getComputers.filteredCount   # Update the total with the real total
        $offset = $limit  * $iteration
        $iteration++                        # Increase iteraction to count the number of cycle and increment $counter
    }
    return $mergeEndpoints
}

## Script Functions
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
    (Optional) A pre-built hash table that maps [GroupName] to [GroupID].
    If provided, the GroupId property will be populated.
    If a group from the CSV is not found in this map, GroupId will be $null.

.OUTPUTS
    [PSCustomObject]
    Streams objects to the pipeline, each with:
    - EpmGroupName (string)
    - GroupId (always $null, as a placeholder)
    - Computers (array of strings)
#>
function ConvertTo-EpmGroupData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({
            if (-not (Test-Path -Path $_ -PathType Leaf)) {
                throw "File not found: $_"
            }
            return $true
        })]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [System.Collections.IDictionary]$GroupLookup = $null
    )

    Write-Log "Starting EPM Group processing for file: $Path" INFO

    $groupMap = @{}

    $headers = 'ComputerName', 'GroupList'
    $csvStream = Import-Csv -Path $Path -Header $headers

    foreach ($row in $csvStream) {
        $computer = $row.ComputerName.Trim()
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

    Write-Log "Grouping complete. Found $($groupMap.Keys.Count) unique groups." INFO

    foreach ($entry in $groupMap.GetEnumerator()) {
        
        $groupId = $null
        if ($null -ne $GroupLookup -and $GroupLookup.ContainsKey($entry.Key)) {
            $groupId = $GroupLookup[$entry.Key]
        }        
        
        # This object is written to the output stream
        [PSCustomObject]@{
            EpmGroupName = $entry.Key
            GroupId      = $groupId
            Computers    = $entry.Value # This is the [List[string]] we built
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

# Check the source file
if (-not (Test-Path $source)) {
    Write-Log "The specified CSV file '$source' was not found." ERROR
    exit 1
}

# Get Static Groups
$compGroupFilter = @{
    "filter" = "type EQ Static"
} | ConvertTo-Json
$getCompGroups = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/groups/search" -Method 'POST' -Headers $sessionHeader -Body $compGroupFilter

$GroupNameToIdMap = @{} # Map of [GroupName] = GroupID
foreach ($compGroup in $getCompGroups) {
    $name = $compGroup.name
    $id = $compGroup.id
    $GroupNameToIdMap[$name] = $id
}

# Get Endpoints
$getEndpoints = Get-EPMEndpoints
$EndpointNameToIdMap = @{} # Map of [EndpointName] = EndpointID

foreach ($endpoint in $getEndpoints.endpoints) {
    $name = $endpoint.name.Trim()
    $id = $endpoint.id
if ($EndpointNameToIdMap.ContainsKey($name)) {
        # Duplicate name found. Temporary Solution.
        # TO DO: Reuse the a function to hanlde dupkiated from otehr script
        Write-Log "Duplicate endpoint name found: '$name'. The ID '$($EndpointNameToIdMap[$name])' will be used, ignoring ID '$id'." WARN
    }
    else {
        $EndpointNameToIdMap[$name] = $id
    }
}

ConvertTo-EpmGroupData -Path $source -GroupLookup $GroupNameToIdMap | ForEach-Object {
    
    $GroupObject = $_
    
    Write-Log "Processing Group: $($GroupObject.EpmGroupName)" INFO
    Write-Log "  Computers: ($($GroupObject.Computers -join ', '))" INFO

    # Convert ComputerName to Computer ID
    $memberIDsList = @()
    foreach ($computerName in $GroupObject.Computers) {
        if ($EndpointNameToIdMap.ContainsKey($computerName)) {
            $memberIDsList += $EndpointNameToIdMap[$computerName]

        } else {
            Write-Log "Computer '$computerName' not found in EPM inventory. Skipping for group '$($GroupObject.EpmGroupName)'." WARN
        }
    }
    
    # Check if we have any valid IDs left to process
    if ($memberIDsList.Count -eq 0) {
        Write-Log "Skipping group '$($GroupObject.EpmGroupName)': No members found in EPM inventory." WARN
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