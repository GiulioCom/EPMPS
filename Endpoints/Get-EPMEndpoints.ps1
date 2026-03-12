<#
.SYNOPSIS
    Retrieves Endpoints information from the CyberArk Endpoint Privilege Manager (EPM).

.DESCRIPTION
    This script connects to a specified EPM tenant, fetches endpoints belonging to a given Set,

.PARAMETER Username
    The EPM username required for session authentication. This is mandatory for establishing a session.
    (Example: user@domain)

.PARAMETER SetName
    The name of the EPM Set whose endpoints you wish to retrieve.

.PARAMETER Tenant
    The EPM tenant region/instance to connect to. Used to construct the correct API URL.
    Input is validated against a known set of regions to prevent injection attacks.
    (Accepted values: login, eu, uk, au, ca, in, jp, sg, it, ch)

.PARAMETER Log
    If specified, enables logging output to both the console and a file defined by $logFolder.

.PARAMETER LogFolder
    The directory path where the log file will be created. Requires the -Log switch to be active.

.PARAMETER DetailsLevel
    Specifies the level of detailed inventory information to fetch for the endpoints.
    If no set, only high-level properties are returned.
    For detailed reports, the script fetches and dynamically flattens the specified inventory field.
    (Accepted values: OsInfo, Hardware, Network, DomainInfo, TerminalSessions, TimeAndDate, UserGroups, InstalledPrograms, ProxySettings, Basic)

.PARAMETER exportCSVFolder
    The folder where the final CSV output file will be saved. A file named 'SETname_Endpoints_Details.csv'
    will be created in this directory.

.LINK
    https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/get-endpoints.htm
    https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/get-multiple-endpoint-details.htm

.EXAMPLE
    1. Retrieve all endpoints
    # The output is saved in the default 'EPMGetEndpointsDetailsExport' folder.
    .\EPMGetEndpointDetails.ps1 -Username 'user@domain.com' -Tenant 'eu'

    2. Retrieve Endpoints with specified Upgrade Status, Failed
    .\EPMGetEndpointDetails.ps1 -Username 'admin@corp.local' -Tenant 'uk' -SetName 'High-Risk Servers' -upgradeStauts Failed

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 03/2026
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

    [Parameter(HelpMessage = "Specify the upgrade status.")]
    [ValidateSet("Initiating", "Pending", "WaitingForDownload", "Downloading", "Installing", "Completed", "Failed", "Aborted")]
    [string]$upgradeStatus = "",

    [Parameter(HelpMessage = "Export path for thge output CSV file")]
    [ValidateScript({
        if (Test-Path $_ -IsValid) { $true } 
        else { throw "Invalid path provided." }
    })]
    [string]$exportCSVFolder
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
        Add-Content -Path $LogFilePath -Value $logMessage
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
        [string]$filter         #Set the search body
    )

    $mergeEndpoints = [PSCustomObject]@{
        endpoints = @()
        filteredCount = 0
        returnedCount = 0
    }

    if ((-not [string]::IsNullOrWhiteSpace($filter))) {
        $filterJSON = @{
            filter = $filter
        } | ConvertTo-Json
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

        # Manage 0 results
        if ($total -eq 0 -and $offset -eq 0) { continue }
        else {
            # Progress Bar
            $Percent = (($offset / $total) * 100)
            Write-Progress -Activity "Retrieving Endpoints $($total) total" -Status "Retrieved: $offset Endpoints" -PercentComplete $Percent
        }
    }
    Write-Progress -Activity "Retrieving Endpoints $($total) total"  -Status "Completed: Successfully retrieved $($mergeEndpoints.filteredCount) Endpoints" -PercentComplete 100 -Completed
    
    return $mergeEndpoints
}

Function Get-EPMPolicies {
<#
.SYNOPSIS
    Retrieves a list of EPM policies from a CyberArk EPM server, handling pagination automatically.

.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get policies.
    It automatically manages pagination by making multiple API calls if the total number
    of policies exceeds the API's maximum limit (1000). The function merges all
    policies into a single PSCustomObject for easy management.

.PARAMETER limit
    The maximum number of policies to retrieve per API call. The default is 1000,
    which is the maximum allowed by the CyberArk EPM API.

.PARAMETER sortBy
    The field by which to sort the policies. Common values include "Updated", "Name",
    and "PolicyType". The default is "Updated".

.PARAMETER sortDir
    The sorting direction. Valid values are "asc" (ascending) and "desc" (descending).
    The default is "desc".

.PARAMETER policyFilter
    A hashtable containing filter criteria for the policies. The keys and values
    must match the JSON format expected by the EPM API's search endpoint.
    Example: @{ "filter" = "PolicyType IN 11,36,37,38" }.

.EXAMPLE
    Get-EPMPolicies -limit 500 -sortBy "Name"

.EXAMPLE
    $myFilter = @{
        "filter" = "PolicyType IN 11,36"
    }
    Get-EPMPolicies -policyFilter $myFilter

.OUTPUTS
    This function returns an object containing the merged policies and metadata.
    The object has the following properties:
        - Policies: An array of all policy objects.
        - ActiveCount: The count of active policies.
        - TotalCount: The total number of policies on the server.
        - FilteredCount: The total number of policies that match the applied filter.

.NOTES
    This function requires a valid session header and manager URL to be accessible
    in the execution context. It uses Invoke-EPMRestMethod.
#>
    param (
        [int]$limit = 1000,         # Set limit to the max size if not declared
        [string]$sortBy = "Updated",
        [string]$sortDir = "desc",
        [hashtable]$policyFilter
    )

    $mergePolicies = [PSCustomObject]@{
        Policies = @()
        ActiveCount = 0
        TotalCount = 0
        FilteredCount = 0
    }

    if ($null -ne $policiesFilter) {
        $policyFilterJSON = $policyFilter | ConvertTo-Json
    }

    $offset = 0             # Offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        $getPolicies = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?offset=$offset&limit=$limit&sortBy=$sortBy&sortDir=$sortDir" -Method 'POST' -Headers $sessionHeader -Body $policyFilterJSON
        
        $mergePolicies.Policies += $getPolicies.Policies            # Merge the current computer list
        $mergePolicies.ActiveCount = $getPolicies.ActiveCount       # Update the ActiveCount
        $mergePolicies.TotalCount = $getPolicies.TotalCount         # Update the TotalCount
        $mergePolicies.FilteredCount = $getPolicies.FilteredCount   # Update the FilteredCount

        $total = $getPolicies.FilteredCount                         # Update the total with the real total
        $offset += $getPolicies.Policies.Count

        # Progress  Bar
        $Percent = [int](($offset / $total) * 100)
        Write-Progress -Activity "Retrieving Policies $($total) total" -Status "Retrieved: $offset Policies" -PercentComplete $Percent
    }
    Write-Progress -Activity "Retrieving Policies $($total) total"  -Status "Completed: Successfully retrieved $($mergePolicies.FilteredCount) Policies" -PercentComplete 100 -Completed

    return $mergePolicies
}

## Utility Functions
function ConvertTo-FlatObject {
<#
.SYNOPSIS
    Recursively flattens objects
#>
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$InputObject,

        [string]$Prefix = ""
    )

    $properties = [ordered]@{}

    $pso = $InputObject.psobject

    foreach ($prop in $pso.Properties) {
        $propName = $prop.Name
        $propValue = $prop.Value
        
        $newKey = if ([string]::IsNullOrEmpty($Prefix)) { $propName } else { "${Prefix}_${propName}" }
        

        if ($null -eq $propValue) {
            $properties[$propName] = $null
        } elseif ($propValue -is [System.Management.Automation.PSCustomObject] -or $propValue -is [System.Collections.Hashtable]) {

            $nestedProps = ConvertTo-FlatObject -InputObject ([pscustomobject]$propValue) -Prefix $newKey
            foreach ($key in $nestedProps.Keys) {
                $properties[$key] = $nestedProps[$key]
            }
        }
        else {
            $properties[$newKey] = $propValue
        }
    }

    return $properties
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
}
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

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

Write-Log "Getting Endpoints List from set '$($set.setName)'" INFO
$filter = ""
if (-not [string]::IsNullOrWhiteSpace($upgradeStatus)) { $filter = "upgradeStatus EQ $upgradeStatus" } 
$EndpointsList = Get-EPMEndpoints -filter $filter

if ($EndpointsList.returnedCount -eq 0) {
    Write-Log "No Endpoints Found!" WARN
} else {
    $EndpointsList.endpoints | ConvertTo-Csv -NoTypeInformation

    if (-not [string]::IsNullOrWhiteSpace($exportCSVFolder)) {
        $fileName = "Report_$($set.setName)__Endpoints_$upgradeStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $fullPath = Join-Path -Path $exportCSVFolder -ChildPath $fileName
        Write-Log "Saving Endpoints CSV file in '$fullPath'" INFO
        $EndpointsList.endpoints | Export-Csv -Path $fullPath -NoTypeInformation
    }   
}

