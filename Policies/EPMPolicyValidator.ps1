<#
.SYNOPSIS
    This script validates EPM applications definition.

.DESCRIPTION
    The EPMPolicyValidator script aims to scan policies or application groups, collect information about
    the application definitions, and validate them. It operates in two modes:

    1. **Audit Mode**: Analyzes the Audit SET Admins events for policy changes and processes only the modified
       policies. This mode is useful for continuous analysis of policies upon administrator modifications and is
       suggested to be used as a scheduled task running every 5 minutes.
    
    2. **Manual Scan Mode**: Performs a one-time scan of policies for testing or health checks. The script can
       manually scan all application groups and policies, only application groups, only policies, or specific
       policies or application groups.

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

.PARAMETER ScanPolicies
    Mandatory: No
    Specifies the type of policy scanning to perform. Valid values are 'all', 'appgroups', or 'policies'.

.PARAMETER name
    Mandatory: No
    Specifies the name of the policy or application group when using the -ScanPolicies parameter.

.EXAMPLE
    1. Audit Mode:
        .\EPMPolicyValidator.ps1 -username "user@domain" -tenant "eu" -destinationFolder "C:\Data"
    2. Manual Mode:
        .\EPMPolicyValidator.ps1 -username "user@domain" -tenant "eu" -ScanPolicies "all"

.NOTES
    File: EPMPolicyValidator.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.6
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

    [Parameter(HelpMessage = "Please provide the destination folder to store and read the last event details. Mandatory when read data from Admin Audit")]
    [string]$destinationFolder,

    [Parameter(HelpMessage = "Scan policies option: 'all', 'appgroups', or 'policies'")]
    [ValidateSet("all", "appgroups", "policies")]
    [string]$ScanPolicies,

    [Parameter(HelpMessage = "Policy \ App Group name, to be used with -ScanPolicies if needed")]
    [string]$name,

    [Parameter(HelpMessage = "set slow mode")]
    [switch]$pause,

    [Parameter(HelpMessage = "Output only for not compliant definitions")]
    [switch]$notCompliant,

    [Parameter(HelpMessage = "Export result in CSV file")]
    [switch]$exportCSV
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
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 120
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) {
        try {
            # Write-Log "Attempt #$($retryCount + 1): Calling API: $URI with Method: $Method" INFO
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

            # Handle rate limit error (EPM00000AE)
            if ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
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
    $iteration = 1          # Define the number of iteraction, used to increase the offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        $getComputers = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers?offset=$offset&limit=$limit" -Method 'GET' -Headers $sessionHeader
        
        $mergeComputers.Computers += $getComputers.Computers    # Merge the current computer list
        $mergeComputers.TotalCount = $getComputers.TotalCount   # Update the TotalCount

        $total = $getComputers.TotalCount   # Update the total with the real total
        $offset = $limit  * $iteration
        $iteration++                        # Increase iteraction to count the number of cycle and increment $counter
    }
    return $mergeComputers
}

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
Function Get-EPMPolicies {
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

function Evaluate-Patterns {
    param (
        [object]$Application,
        [string]$PatternName,
        [int]$Priority
    )

    $result = [PSCustomObject]@{
        PatternName = $PatternName
        Weight = 0
        value = ""
    }

    $compareAsMapping = @{
        0 = "exact"
        1 = "prefix"
        2 = "contains"
        3 = "wildcards"
        4 = "regExp"
    }

    # Manage use case
    if (!$Application.patterns.$PatternName.isEmpty) {
        
        $result.Weight = $Priority
        $result.value = $Application.patterns.$PatternName.content

        # Manage exceptions

        # Reduce weight if the compareAs is not EXACTLY
        # But before, check compareAs is available (for example the property LOCATION doesn't have it)
        if ($null -ne $Application.patterns.$PatternName -and $null -ne $Application.patterns.$PatternName.compareAs) {
            if ($Application.patterns.$PatternName.compareAs -ne 0) {
                $result.Weight = $result.Weight / 2
            }
        }
        
        # Publisher: Reduce weight if the publisher is not SPECIFIC
        if ($PatternName -eq "PUBLISHER") {
            if ($Application.patterns.PUBLISHER.signatureLevel -ne 2) {
                $result.Weight = $result.Weight / 2
            }
        }
        # Location: Reduce the weight if subfolders are enabled
        if ($PatternName -eq "LOCATION") {
            if ($Application.patterns.LOCATION.withSubfolders -eq $true) {
                $result.Weight = $result.Weight / 2
            }
        }
        # Owner: Get the correct value
        if ($PatternName -eq "OWNER") {
            foreach ($account in $Application.patterns.$PatternName.accounts){
                $result.value += "$($account.name) "
            }
        }
    }

    return $result
}

function Process-Application{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [object]$Application,
        [string]$PolicyType,
        [string]$Action
    )

    $AppTypeMapping = @{
        2 = "Group"             # Patterns: None
        3 = "EXE"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, File description, Company name, Original file name, File version, Product version, File origin (Source), Parent, Service name (must be empty)
        4 = "Script"            # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, File origin (Source), Parent
        5 = "MSI"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, Company name, Product code, Upgrade code, Product version, File origin (Source), Parent
        6 = "MSU"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, File origin (Source), Parent
        7 = "WebApp"            # Patterns: URL
        8 = "WinAdminTask"      # Patterns: Admin task ID
        9 = "ActiveX"           # Patterns: File name, Publisher, Code URL, Mime type, CLSID, Version
        13 = "FileSystemNode"   # Patterns: File name or Location
        14 = "Registry Key"     # Patterns: Registry key
        15 = "COM"              # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, CLSID
        17 = "WinService"       # Patterns: Service name
        18 = "USB Device"       # Patterns: Vendor Id, Vendor Name, Product Id, Product Name, Instance Id
        19 = "Optical Disc2"    # Patterns: Instance Id
        20 = "WinApp"           # Patterns: Publisher, App package name, App package version, Capabilities
        21 = "DLL"              # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, File description, Company name, Original file name, File version, Product version, File origin (Source), Parent
        22 = "macPKG"           # Patterns: File name, Location, Publisher, Mac DMG image
        23 = "MacSysPref"       # Patterns: Admin task ID
        24 = "MacApplication"   # Patterns: File name, Location, Publisher, Bundle ID, Bundle version
        26 = "MacDMG"           # Patterns: File name, Location, Publisher
        28 = "Linux command"    # Patterns: File name, Arguments, Location, Linux link name, Linux script interpreter, Linux run as user
        104 = "MacSUDO"         # Patterns: File name, Arguments, Publisher
    }
   
    # Define the priority weight
    $priority1 = 30
    $priority2 = 20
    $priority3 = 10

    # Set the threshold, the value can change based on policy type or policy action
    $threshold = 0
    
    # Policy type Linux or MacOS 60, Windows = 90
    if ($PolicyType -eq 12 -or $PolicyType -eq 13) {
        $threshold = 60
    } else {
        $threshold = 90
    }
    
    # Policy action allow or deny
    if ($action -eq 2 -or $action -eq 1) {
        $threshold = 30
    }
    
    $unspportedAppType = $false    

    $matchedConditions = @()
    $totalWeight = 0

    $appTypeName = $AppTypeMapping[$Application.applicationType]

    # Evaluate Patterns based on application type, 
    switch ($appTypeName) {
        'EXE' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "FILE_DESCRIPTION" $priority2
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "ORIGINAL_FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'Script' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'MSI' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'MSU' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'ActiveX' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "CLSID" $priority3
        }
        'COM' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "CLSID" $priority3
        }
        'WinApp' {
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'DLL' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "FILE_DESCRIPTION" $priority2
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "ORIGINAL_FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'macPKG' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacApplication' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacDMG' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacSUDO' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'Linux command' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LINUX_LINK_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "LINUX_SCRIPT_INTERPRETER" $priority2
        }
        default {
            # Default action if none of the conditions match
            Write-Log "Application Type '$appTypeName' not supported." WARN
            $unspportedAppType = $true
        }
    }

    if (!$unspportedAppType) {
        # Evaluate common pattern, such as HASH
        switch ($appTypeName) {
            { ($_ -eq "EXE") -or ($_ -eq "Script") -or ($_ -eq "MSI") -or ($_ -eq "MSU") -or ($_ -eq "COM") -or ($_ -eq "DLL") -or 
              ($_ -eq "Linux command") -or ($_ -eq "macPKG") -or ($_ -eq "MacApplication") -or ($_ -eq "MacDMG") -or ($_ -eq "MacSUDO")} {
                if ($Application.patterns.FILE_NAME.hash) {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "HASH"
                        Weight = "90"
                        value = $Application.patterns.FILE_NAME.hash
                    }
                }
            }
        }
    
        # Calculate Total value
        $totalWeight = ($matchedConditions | Measure-Object -Property Weight -Sum).Sum
<#        
        foreach ($condition in $matchedConditions) {
            $totalWeight += $condition.Weight
        }
#>    
        # Evaluate global pattern, such as child process
        switch ($appTypeName) {
            { ($_ -eq "EXE") -or ($_ -eq "Script") -or ($_ -eq "DLL") } {
            # If child process is enabled divide the total
                if ($Application.childProcess -eq $true) {
                    $totalWeight = $totalWeight / 2
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "WIN_CHILD_PROCESS"
                        Weight = -$totalWeight
                        value = "Enabled"
                    } 
                } else {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "WIN_CHILD_PROCESS"
                        Weight = -0
                        value = "Disabled"
                    }
                }                
            }
            'Linux command' {
                # Linux  Child Process   
                $linuxChildProcessMapping = @{
                    0 = "Deny"
                    1 = "Allow"
                    2 = "Allow and Restrict"
                }

                switch ($Application.LinuxChildProcess) {
                    0 { $totalWeight = $totalWeight }
                    1 { $totalWeight = $totalWeight / 2 }
                    2 { $totalWeight = $totalWeight / 2 }
                }
                $linuxChildProcessName = $linuxChildProcessMapping[$Application.LinuxChildProcess]
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "LIN_CHILD_PROCESS"
                    Weight = -$totalWeight
                    value = "$linuxChildProcessName"
                }
            
                # Linux Sudo no password
                if ($Application.linuxSudoNoPassword -eq $true) {
                    $totalWeight = $totalWeight / 2
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "LIN_SUDO_NO_PASSWORD"
                        Weight = -$totalWeight / 2
                        value = "Enabled"
                    }
                } else {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "LIN_SUDO_NO_PASSWORD"
                        Weight = -0
                        value = "Disabled"
                    }
                }
            }
        }
        
        # Define the application name for better output
        $applicationName = $null

        # Define the priority order for pattern names
        $priorityPatterns = @("FILE_NAME", "ORIGINAL_FILE_NAME", "PUBLISHER")

        foreach ($pattern in $priorityPatterns) {
            $matchingCondition = $matchedConditions | Where-Object { $_.PatternName -eq $pattern }

            if ($matchingCondition) {
                $applicationName = $Application.patterns.$($pattern).content
                break
            }
        }
<#
        foreach ($condition in $matchedConditions) {
            if ($condition.Weight -ge 15) {
                switch ($condition.PatternName) {
                    "FILE_NAME" {
                        $applicationName = $Application.patterns.FILE_NAME.content
                        break
                    }
                    "ORIGINAL_FILE_NAME" {
                        $applicationName = $Application.patterns.ORIGINAL_FILE_NAME.content
                        break
                    }
                    "PUBLISHER" {
                        $applicationName = $Application.patterns.PUBLISHER.content
                        break
                    }
                }
                if ($applicationName) {
                    break  # Stop the loop if $applicationName is assigned
                }
            }
        }
#>        
        if (-not $applicationName) {
            # If none of the conditions matched, assign $Application.id
            $applicationName = $Application.id
        }      
        
        If ($totalWeight -ge $threshold) {
            if (!$notCompliant) {
                Write-Log "> $applicationName - $totalWeight - Compliant to Policy Standards" -severity INFO -ForegroundColor Green
                Write-Log "|-> Application Type: $appTypeName" -severity INFO -ForegroundColor Gray
                Write-Log "|-> Application Description: $($Application.description)" -severity INFO -ForegroundColor Gray
                # Iterate through each $matchedConditions
                foreach ($condition in $matchedConditions) {
                    # Print PatternName when weight is greater than 0
                    if ($condition.Weight -ne 0) {
                        Write-Log "|-> $($condition.PatternName): $($condition.value) = $($condition.Weight)" -severity INFO -ForegroundColor Gray
                    }
                }
            }
        } else {
            Write-Log "> $applicationName - $totalWeight - Not Compliant to Policy Standards" -severity WARN -ForegroundColor Yellow
            Write-Log "|-> Application Type: $appTypeName" -severity WARN -ForegroundColor Gray
            Write-Log "|-> Application Description: $($Application.description)" -severity WARN -ForegroundColor Gray
            # Iterate through $matchedConditions
            foreach ($condition in $matchedConditions) {
                # Print PatternName if Weight is greater than 0
                if ($condition.Weight -ne 0) {
                    Write-Log "|-> $($condition.PatternName): $($condition.value) = $($condition.Weight)" -severity WARN -ForegroundColor Gray
                }
            }
        }
    }

    if ($pause) {
        Write-Host "Press Enter to continue..."
        $null = Read-Host
    }

    return [PSCustomObject]@{
        ApplicationName = $applicationName
        ApplicationType = $appTypeName
        TotalWeight     = $totalWeight
    }
}

<#
.SYNOPSIS
Retrieves information about policies from a management system using REST API calls.

.DESCRIPTION
The Get-PolicyInfo function retrieves information about policies from a management system using REST API calls. It allows querying policies based on specified criteria such as policy name, set ID, and feature type. Depending on the feature type, it searches for policies either within application groups or directly within the policies.

.PARAMETER managerURL
The URL of the management system.

.PARAMETER Headers
Headers to be included in the HTTP request.

.PARAMETER setID
The ID of the policy set.

.PARAMETER policyName
The name of the policy to retrieve.

.PARAMETER feature
The type of feature to search for. Accepted values: "Application Groups", "Policy".

.OUTPUTS
Information about policies and their associations.

.NOTES
- The function uses REST API calls to interact with the management system.
- It relies on helper functions Invoke-EPMRestMethod and Process-Application for certain operations.

.EXAMPLE
Get-PolicyInfo -managerURL "https://example.com" -Headers @{ "Authorization" = "Bearer token" } -setID "123456" -policyName "PolicyName" -feature "Application Groups"
This command retrieves information about policies associated with the specified policy name within application groups.
#>
function Get-PolicyInfo {
    param (
        [string]$managerURL,
        [hashtable]$Headers,
        [string]$setID,
        [string]$policyName,
        [string]$feature,
        [object]$appGroupList,
        [object]$policesList
    )

    $actionMapping = @{
        1 = "Allow"
        2 = "Block"
        3 = "Elevate"        
        4 = "Elevate if necessary"
        5 = "CollectUAC"
        6 = "ElevateRequest"
        9 = "ExecSript"
        10 = "AgentConfiguration"
        11 = "SetSecurityPermissions"
        13 = "DefineUpdater"
        17 = "Loosely connected devices"
        18 = "DefineDeveloperTool"
        20 = "AdHocElevate"
    }

    $policyType = @{
        1 =	"Privilege Management Detect"
        2 =	"Application Control Detect"
        3 =	"Application Control Restrict"
        4 =	"Ransomware Protection Detect"
        5 =	"Ransomware Protection Restrict"
        6 =	"INT Detect"
        7 =	"INT Restrict"
        8 =	"INT Block"
        9 =	"Privilege Management Elevate"
        10 = "Application Control Block"
        11 = "Advanced Windows"
        12 = "Advanced Linux"
        13 = "Advanced Mac"
        17 = "Recommended Block Windows OS Applications"
        18 = "Predefined App Groups Win"
        20 = "Developer Applications"
        22 = "Credentials Rotation"
        23 = "Trusted Install Package Windows"
        24 = "Trusted Distributor Windows"
        25 = "Trusted Updater Windows"
        26 = "Trusted User/Group Windows"
        27 = "Trusted Network Location Windows"
        28 = "Trusted URL Windows"
        29 = "Trusted Publisher Windows"
        30 = "Trusted Product Windows"
        31 = "Trusted Distributor Mac"
        32 = "Trusted Publisher Mac"
        36 = "User Policy - Set Security Permissions for File System and Registry Keys"
        37 = "User Policy - Set Security Permissions for Services"
        38 = "User Policy - Set Security Permissions for Removable Storage (USB, Optical Discs)"
        39 = "Collect UAC actions by Local Admin"
        40 = "JIT Access and Elevation"
        41 = "Deploy Script"
        42 = "Execute Script"
        45 = "Agent Configuration"
        46 = "Remove Admin"
        47 = "Deception"
    }

    $applicationGroupType = @{
        14 = "Application Group Win"
        15 = "Application Group Linux"
        16 = "Application Group Mac"
        19 = "Microsoft Windows Programs (Win Files)"
        21 = "Authorized Applications (Ransomware)"
        33 = "Trusted Distributor Predefined Definition Win"
        34 = "Trusted Updater Predefined Definition Win"
        35 = "Trusted Distributor Predefined Definition Mac"
        43 = "Predefined App Groups Win"
    }

    # Define supported Application Group
    $allowedApplicationGroupType = @(14, 43, 15, 16)
    $supportedApplicationGroupTypes = $allowedApplicationGroupType | Where-Object { $applicationGroupType.ContainsKey($_) } | ForEach-Object { $applicationGroupType[$_] }

    # Define supported Policy Type
    $allowedPolicyType = @(11, 18, 12, 13)
    $supportedPolicyTypes = $allowedPolicyType | Where-Object { $policyType.ContainsKey($_) } | ForEach-Object { $policyType[$_] }
    
    
    # Construct the base URI for API calls
    $policiesURI = "$managerURL/EPM/API/Sets/$setID/Policies"

    # Retrieve policy list based on the feature type
    if ($feature -eq "Application Groups") {
        # Search AppGroup
        $appGroup = $appGroupList.Policies | Where-Object { $_.PolicyName -eq $policyName } | ForEach-Object {
            if ($allowedApplicationGroupType -contains $appGroup.PolicyType) {
                # Get Application Group Details
                $appGroupDetails = Invoke-EPMRestMethod -Uri "$policiesURI/ApplicationGroups/$($appGroup.PolicyId)" -Method 'GET' -Headers $Headers

                # Search policy where the app ID is included
                $matchingPolicies = $policiesList.Policies | Where-Object { 
                    $_.ReferencedApplicationGroups.Where({ $_.Id -eq $appGroup.PolicyId -and $_.ReferenceType -eq 1 }).Count -gt 0
                } 
                if ($matchingPolicies) {
                    foreach ($policy in $matchingPolicies) {
                        $policyTypeName = $policyType[$policy.PolicyType]
                        $policyAction = $actionMapping[$policy.Action]
                        Write-Log "Application group '$($appGroup.PolicyName)' was found in policy '$($policy.PolicyName)', categorized as '$policyTypeName' with action '$policyAction'." -severity INFO -ForegroundColor Green

                        # Filter by Allowed Policies
                        if ($allowedPolicyType -contains $policy.PolicyType) {
                            if ($appGroupDetails.Policy.Applications -gt 0) {
                                foreach ($application in $appGroupDetails.Policy.Applications) {
                                    $result = Process-Application -Application $application -PolicyType $($policy.PolicyType) -action $($policy.Action)

                                    if ($exportCSV) {
                                        $exportCSVData = [PSCustomObject]@{
                                            PolicyName      = $policyDetails.Policy.Name
                                            Type            = $policyType[$policyDetails.Policy.PolicyType]
                                            PolicyAction    = $actionMapping[$policyDetails.Policy.Action]
                                            ApplicationName = $result.ApplicationName
                                            ApplicationType = $result.ApplicationType
                                            TotalWeight     = $result.totalWeight
                                        }
                                        $exportCSVData | Export-Csv -Path $exportCSVFilePath -Append -NoTypeInformation -Encoding UTF8
                                    }
                                }
                            } else {
                                Write-Log "Application Group '$($appGroup.PolicyName)' is empty." WARN
                            }
                        } else {
                            Write-Log "Policy '$($policy.PolicyName)' not supported. The supported policy types are: $($supportedPolicyTypes -join ', ')" WARN
                        }
                    }
                }
            } else {
                Write-Log "Application Group '$($appGroup.PolicyName)' not supported. The supported application group type are $($supportedApplicationGroupTypes -join ', ')" WARN
            }    
        }
    } else {
        #Search policy
       # $policyFound = $false
        $policy = $policiesList.Policies | Where-Object { $_.PolicyName -eq $policyName } | ForEach-Object {
            $policyTypeName = $policyType[$policy.PolicyType]
            $policyAction = $actionMapping[$policy.Action]
            Write-Log "Policy '$policyName' was found, categorized as '$policyTypeName' with action '$policyAction'" INFO

            # Filter by Allowed Policies type
            if ($allowedPolicyType -contains $policy.PolicyType) {
              #  $policyFound = $true
                $policyDetails = Invoke-EPMRestMethod -Uri "$policiesURI/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
                foreach ($application in $policyDetails.Policy.Applications) {
                    $result = Process-Application -Application $application -PolicyType $($policy.PolicyType) -action $($policy.Action)
                    if ($exportCSV) {
                        $exportCSVData = [PSCustomObject]@{
                            PolicyName      = $policyDetails.Policy.Name
                            Type            = $policyType[$policyDetails.Policy.PolicyType]
                            PolicyAction    = $actionMapping[$policyDetails.Policy.Action]
                            ApplicationName = $result.ApplicationName
                            ApplicationType = $result.ApplicationType
                            TotalWeight     = $result.totalWeight
                        }
                        $exportCSVData | Export-Csv -Path $exportCSVFilePath -Append -NoTypeInformation -Encoding UTF8
                    }
                }
            } else {
                Write-Log "Policy '$PolicyName' not supported. The supported policy types are: $($supportedPolicyTypes -join ', ')" WARN
            }
        }
        #}
        
    #    if ($policyFound -eq $false) {
    #        Write-Log "Policy '$PolicyName' not supported. The supported policy types are: $($supportedPolicyTypes -join ', ')" -severity WARN -ForegroundColor Yellow
    #    }
    }
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
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $PSBoundParameters.ContainsKey('logFolder')) {
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

# Prepare Export CSV file
# Set the path for the CSV file.
$exportCSVFileName = "$scriptName`_$($set.SetName)`_$timestamp.csv"
$exportCSVFilePath = Join-Path $scriptDirectory $exportCSVFileName
if ($exportCSV) {
    $header = [PSCustomObject]@{
        PolicyName      = $null
        PolicyType      = $null
        PolicyAction    = $null
        ApplicationName = $null
        ApplicationType = $null
        TotalWeight     = $null
    }

    if (-not (Test-Path $exportCSVFilePath)) {
        $header | Export-Csv -Path $exportCSVFilePath -NoTypeInformation -Encoding UTF8
        Write-Log "Export CSV file initialized in '$exportCSVFilePath'." INFO
    } else {
        Write-Log "File '$exportCSVFilePath' already exists. Skipping initialization." INFO
    }    
}

Write-Box "$scriptName"
Write-Box "Analyzing Set $($set.setName)"

# Check if the -ScanPolicies switch is present
if ($PSBoundParameters.ContainsKey('ScanPolicies')) {
    switch ($ScanPolicies) {
        "all" {
            # Perform actions for scanning all policies
            Write-Box "Scanning Policies and Application Groups."

            # Get Application Groups
            $appGroupsFilter = @{
                "filter" = "PolicyGroupType EQ 10" # Application Group -> Custom Application Group, Predefined App Group, Predefined Trusted Source 
            }  | ConvertTo-Json
            $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
            
            # Get Policies
            $policiesFilter = @{
                "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
            }  | ConvertTo-Json    
            $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

            Write-Log "Analzying Application Groups..." -severity INFO -ForegroundColor DarkCyan
            Write-Log "Retrieved $($appGroupList.FilteredCount) Application Groups..." -severity INFO -ForegroundColor DarkCyan

            $appGroupsCounter = 1

            foreach ($appGroup in $appGroupList.Policies) {
                Write-Log "Analyzing $appGroupsCounter of $($appGroupList.FilteredCount) Application Group - '$($appGroup.PolicyName)'" -severity INFO -ForegroundColor DarkCyan
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($appGroup.PolicyName) -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
                $appGroupsCounter++
            }

            # Get Policyes list
            Write-Log "Analzying Application Policies..." -severity INFO -ForegroundColor DarkCyan
            Write-Log "Retrieved $($policiesList.FilteredCount) Application Policies..." -severity INFO -ForegroundColor DarkCyan

            $policyCounter = 1
            
            foreach ($policy in $policiesList.Policies) {
                Write-Log "Analyzing $policyCounter of $($policiesList.FilteredCount) Policy - $($policy.PolicyName)" -severity INFO -ForegroundColor DarkCyan
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($policy.PolicyName) -feature "Server" -policiesList $policiesList
                $policyCounter++
            }
        }
        "appgroups" {
            # Perform action for scanning by application group
            if ($PSBoundParameters.ContainsKey('name')) {
                # Perform actions for scanning selected application group
                Write-Log "Scanning by Application Group: $($name)" -severity INFO -ForegroundColor DarkCyan

                # Get the Application Group
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader

                # Get the Policies
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $name -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
            } else {
                # Perform actions for scanning all application groups
                Write-Log "Analyzing all Application Groups..." -severity INFO -ForegroundColor DarkCyan

                $appGroupsFilter = @{
                    "filter" = "PolicyGroupType EQ 10" # Application Group -> Custom Application Group, Predefined App Group, Predefined Trusted Source 
                }  | ConvertTo-Json
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
                
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json    
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

                $appGroupsCounter = 1
                # Get Application Groups
                foreach ($appGroup in $appGroupList.Policies) {
                    Write-Log "Analyzing $appGroupsCounter of $($appGroupList.FilteredCount) Application Group - $($appGroup.PolicyName)" -severity INFO -ForegroundColor DarkCyan
                    Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($appGroup.PolicyName) -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
                    $appGroupsCounter++
                }
            }
        }
        "policies" {
            # Perform action for scanning by policy name
            if ($PSBoundParameters.ContainsKey('name')) {
                # Perform actions for scanning selected policy name
                Write-Log "Scanning by Policy: $name" -severity INFO -ForegroundColor DarkCyan

                # Get the Application Group
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader

                # Get the Policies
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $name -feature "Server" -appGroupList $appGroupList -policiesList $policiesList
            } else {
                # Perform actions for scanning all policies
                Write-Box "Scanning all Policies."

                # Get Policies list
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json    
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

                $policyCounter = 1
                
                foreach ($policy in $policiesList.Policies) {
                    Write-Log "Analyzing $policyCounter of $($policiesList.FilteredCount) Policy - $($policy.PolicyName)" -severity INFO -ForegroundColor DarkCyan
                    Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($policy.PolicyName) -feature "Server" -policiesList $policiesList
                    $policyCounter++
                }
            }
        }
        default {
            Write-Log "Invalid value for -ScanPolicies. Accepted values are 'All', 'AppGroup', 'Policies'." -severity ERROR -ForegroundColor Red
            exit
        }
    }
# Default mode: Perform scan from SetAdmin Audit
} else {

    $appGroupList = ""
    $policiesList = ""
    $eventsNumber = 0
    $lastEventTime
    $filename = "lastProcessedEvent.txt"

    # Check if the 'DestinationFolder' parameter is provided
    if (!$PSBoundParameters.ContainsKey('DestinationFolder')) {
        do {
            # Prompt the user to enter the destination folder
            $destinationFolder = Read-Host -Prompt "Please provide the destination folder to store data"
            
            # Check if the provided value is valid
            if ([string]::IsNullOrWhiteSpace($destinationFolder)) {
                Write-Log "Destination folder is required." -severity ERROR -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($destinationFolder))
    }

    # Prepare destination Folder used to store Last Events Time analyzed
    # Sanitize SET name, could contain charater not allowed
    $destSetName = $set.SetName -replace ('\[|\]|\/', '')
    $destinationFolder = "$destinationFolder\$destSetName"
    $lastProcessedEventFile = Join-Path -Path $destinationFolder -ChildPath $filename

    # Create Folder
    try {
        New-Item -ItemType Directory -Path $destinationFolder -Force -ErrorAction Stop | Out-Null
    } catch {
        # Handle errors if necessary
        Write-Log "Error creating directory: $_." -severity ERROR -ForegroundColor Red
    }

    # Check the file
    try {
        # Check if the file exists
        
        if (!(Test-Path -Path $lastProcessedEventFile -PathType Leaf)) {
            # If the file does not exist, continue with the rest of the code
            Write-Log "The $filename file does not exist in the folder." -severity WARN -ForegroundColor Yellow
        } else {
            $lastEventTime = Get-Content -Path $lastProcessedEventFile -TotalCount 1
        }
    } catch {
        # Handle errors if necessary
        Write-Log "Error loading $filename." -severity ERROR -ForegroundColor Red
    }

    if ([string]::IsNullOrWhiteSpace($lastEventTime)) {
        $URLParm = "Limit=500"
    } else {
        $URLParm = "DateFrom=$lastEventTime"
    }

    $setAdminsAudits = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/AdminAudit?$URLParm" -Method 'GET' -Headers $sessionHeader

    # Order events by EventTime
    $setAdminsAuditsSortByEventTime = $setAdminsAudits.AdminAudits | Sort-Object -Property EventTime
    
    # Write-Host "Searching for Audit Events..." -ForegroundColor DarkMagenta
    Write-Log "Searching for Audit Events..." -severity INFO -ForegroundColor DarkCyan
    foreach ($setAdminsAudit in $setAdminsAuditsSortByEventTime) {
        if ($setAdminsAudit.PermissionDescription -eq "Create Policy" -or $setAdminsAudit.PermissionDescription -eq "Change Policy") {
            $pattern = '.*\"(.*?)\".*'
            if ($setAdminsAudit.Description -match $pattern) {
                $policyName = $Matches[1]
                $eventsNumber++
                Write-Log "$eventsNumber. $($setAdminsAudit.Feature): $policyName" -severity INFO -ForegroundColor DarkCyan
                
                # Get the Application Group only the first time to reduce the EPM request
                if ($appGroupList -eq "") {
                    $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader
                }

                # Get the Policies only the first time to reduce the EPM request
                if ($policiesList -eq "") {
                    $policiesFilter = @{
                        "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                    }  | ConvertTo-Json
                    $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                }
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $policyName -feature $($setAdminsAudit.Feature) -appGroupList $appGroupList -policiesList $policiesList
            } else {
                Write-Log "No match found for $($setAdminsAudit.Description)." -severity WARN -ForegroundColor Yellow
            }
        }

        # Update last event time
        $lastEventTime = $setAdminsAudit.EventTime
    }

    # Provide events results
    if ($eventsNumber -eq 0) {
        Write-Log "No event processed" -severity INFO -ForegroundColor Gray
    } else {
        Write-Log "Processed $eventsNumber events" -severity INFO -ForegroundColor Gray
    }

    # Write the value of $lastEventTime to the lastProcessedEvent.txt file
    try {
        $lastEventTime | Set-Content -Path $lastProcessedEventFile -Encoding UTF8 -ErrorAction Stop
        Write-Log "Successfully wrote last event time to $lastProcessedEventFile" -severity INFO -ForegroundColor Gray
    } catch {
        Write-Log "Error writing to $lastProcessedEventFile" -severity ERROR -ForegroundColor Red
    }
}
