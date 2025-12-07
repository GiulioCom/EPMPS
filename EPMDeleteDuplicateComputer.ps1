<#
.SYNOPSIS
    Remove Duplicate Computer Object in EPM Console

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER delete
    Flag to enabled computer deletion

.NOTES
    File: EPMDuplicateComputer.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 04/2024
    Update: 10/2025
        -   Update API
        -   Update base functions
    Update: 11/2025
        - Improve performance duplicate endpoints
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
    [string]$logFolder,

    [Parameter(HelpMessage="Delete duplicated Endpoint")]
    [switch]$delete = $false
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
                $errorMessage = $ErrorDetailsMessage.ErrorMessage
                
                if ($errorMessage -like "*Limit of the API calls exceeded*") {
                    Write-Log "Rate limit permanently exceeded. Please wait a while before running again." ERROR
                    return
                }

                $pattern = '(\d+)\s+minute' 
                $match = [regex]::Match($errorMessage, $pattern)

                if ($match.Success) {
                    $minutes = [int]$match.Groups[1].Value
                    [int]$RetryDelay = $minutes * 60
                    
                    Write-Log "$errorMessage - Retrying in $RetryDelay seconds (Attempt $($retryCount + 1))..." WARN

                    Start-Sleep -Seconds $RetryDelay
                    $retryCount++
                } else {
                    Write-Log "Rate limit error (EPM00000AE) encountered: $errorMessage." ERROR
                    return
                }
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
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

Write-Box "$($set.setName)"


## Processing Endpoints (New API)
Write-Log "Working on Endpoints." INFO
$getEndpointsList = Get-EPMEndpoints

Write-Log "Searching for duplicated..." INFO

$DuplicatedEndpoints = [System.Collections.Generic.List[Object]]::new()
$LatestEndpoints   = @{} # Key = Computer Name (Endpoint.name), Value = Endpoint Object

foreach ($Endpoint in $getEndpointsList.endpoints) {
    
    $Name = $Endpoint.Computer
    
    $CurrentDate = $Endpoint.lastDisconnected -as [DateTime]
    if (-not $CurrentDate) { $CurrentDate = [DateTime]::MinValue }
    
    # Add a temporary property for easy comparison
    $Endpoint | Add-Member -MemberType NoteProperty -Name "_ParsedDate" -Value $CurrentDate -Force

    if ($LatestEndpoints.ContainsKey($Name)) {
        $ExistingEndpoint = $LatestEndpoints[$Name]
        
        if ($Endpoint._ParsedDate -gt $ExistingEndpoint._ParsedDate) {
            $DuplicatedEndpoints.Add($ExistingEndpoint)
            $LatestEndpoints[$Name] = $Endpoint
        }
        else {
            $DuplicatedEndpoints.Add($Endpoint)
        }
    }
    else {
        $LatestEndpoints[$Name] = $Endpoint
    }
}

Write-Log "Identified $($DuplicatedEndpoints.Count) duplicated endpoints to remove." INFO

$IdList = @()
foreach ($Dup in $DuplicatedEndpoints) {
    $EndpointInfoMessage = "$($Dup.name) - ID: $($Dup.id) (LastSeen: $($Dup.lastDisconnected), Version: $($Dup.version))"

    if ($Dup.id -eq "00000000-0000-0000-0000-000000000000") {
        Write-Log "Agent not compatible with Endpoints. Use MyComputer: $EndpointInfoMessage" WARN
    } else {
        $IdList += [Uri]::EscapeDataString($Dup.id)
        Write-Log "To be deleted (batch): $EndpointInfoMessage" WARN
    }
}

Write-Log "Identified $($IdList.Count) duplicated endpoints to remove." INFO

if ($delete){
    if ($IdList.Count -gt 0) {

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
    
            Write-Log "Processing batch starting with ID $($Batch[0]) (Count: $($Batch.Count), Length: $($FilterString.Length))." INFO
    
            $DeleteBody = @{
                "filter" = $FilterString
            } | ConvertTo-Json

            try {
                $Result = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Endpoints/delete" -Method 'POST' -Headers $sessionHeader -Body $DeleteBody
                $message = "Batch delete executed. Confirmed Deleted $($Result.appliedIds.Count) in a batch of $($Batch.Count)."

                if ($Result.appliedIds.Count -lt $Batch.Count) {
                    Write-Log $message ERROR
                } else {
                    Write-Log $message INFO
                }
            }
            catch {
                Write-Log "Batch deletion failed for starting ID $($Batch[0]): $($_.Exception.Message)" ERROR
            }
        }        
    } else {
        Write-Log "No Duplicated Endpoints" WARN
    }
} else {
        Write-Log "Demo Mode - No deletion" WARN
}

## Processing My Computer (Old API)
Write-Log "Working on 'My Computer'." INFO
$getComputerList = Get-EPMComputers

Write-Log "Searching for duplicated..." INFO

$AgentsToDelete = [System.Collections.Generic.List[Object]]::new() #Generic List for deletion targets, faster than arrays
$LatestAgents   = @{} # Key = ComputerName, Value = AgentObject

foreach ($Agent in $getComputerList.Computers) {
    
    $Name = $Agent.ComputerName
    $CurrentDate = $Agent.LastSeen -as [DateTime]
    if (-not $CurrentDate) { $CurrentDate = [DateTime]::MinValue }
    
    # Add a temporary property to the object so we don't have to convert it again later
    $Agent | Add-Member -MemberType NoteProperty -Name "_ParsedDate" -Value $CurrentDate -Force

    if ($LatestAgents.ContainsKey($Name)) {
        
        $ExistingAgent = $LatestAgents[$Name]
        
        if ($Agent._ParsedDate -gt $ExistingAgent._ParsedDate) {
            $AgentsToDelete.Add($ExistingAgent)
            $LatestAgents[$Name] = $Agent
        }
        else {
            $AgentsToDelete.Add($Agent)
        }
    }
    else {
        $LatestAgents[$Name] = $Agent
    }
}

Write-Log "Identified $($AgentsToDelete.Count) duplicated devices to remove." INFO

foreach ($DuplicatedAgent in $AgentsToDelete) {
    $SafeId = [Uri]::EscapeDataString($DuplicatedAgent.AgentId)
    $TargetUri = "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers/$SafeId"

    $CompInfoMessage = "$($DuplicatedAgent.ComputerName) - ID: $SafeId (LastSeen: $($DuplicatedAgent.LastSeen), Version: $($DuplicatedAgent.AgentVersion))"

    if ($delete) {
        Write-Log "Deleting $CompInfoMessage..." WARN
        
        try {
            # Using try/catch is critical for REST calls to handle 404/500 errors gracefully
            Invoke-EPMRestMethod -Uri $TargetUri -Method 'DELETE' -Headers $sessionHeader -ErrorAction Stop
        }
        catch {
            Write-Log "Failed to delete $SafeId : $_" ERROR
        }
    } 
    else {
        Write-Log "To be deleted $CompInfoMessage" WARN
    }
}