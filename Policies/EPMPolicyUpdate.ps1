<#
.SYNOPSIS
    Demo Script update policy propertiers massively

.DESCRIPTION
    Update Policy proterties:
    - Enable Audit
    - Remove duplicated
    - Remove "[Imported]" prefix
    - Disable policies by readin CSV file


.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMPolicyUpdate.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 1.2
    
    Initial Version: 07/2024
    
    Update: 02/2026
    - Adding disabling policies from file
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

    [Parameter(HelpMessage="Endpoints List (for Disable Policies)")]
    [string]$PoliciesFile,

    [switch]$ShowDebug = $false,

    [switch]$RemoveDuplicatedPolicy,
    [switch]$RemoveImportedFlag,
    [switch]$EnableAudit,
    [switch]$DisablePolicies
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

Function Get-EPMComputers {
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

##############

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

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

if ($EnableAudit) {
    # Retrieve Policies
    # Filter only advanced Windows Policy
    $policiesSearchFilter = @{
        "filter" = "PolicyType EQ ADV_WIN"
    }

    $policySearch = Get-EPMPolicies -policyFilter $policiesSearchFilter

    # Set the Counter
    $policyCounter = 1 
    
    Write-Log "Found $($policySearch.FilteredCount) policies" INFO

    # Process each policy
    foreach ($policy in $policySearch.Policies) {

        Write-Log "Processing $policyCounter of $($policySearch.FilteredCount): '$($policy.PolicyName)'" INFO

        # Filter only the actions: Block, Elevate, Elevate If Necessary
        if ($policy.Action -eq 1 -or $policy.Action -eq 3 -or $policy.Action -eq 4) {
        
            # Retrive the policy
            $getPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
                
            $Audit = $getPolicyDetails.Policy.Audit
            if ($Audit -ne $true) {
                Write-Log "$($policy.PolicyName): Audit disabled" INFO
                
                $getPolicyDetails.Policy.Audit = $true
                Write-Log "$($policy.PolicyName): Enabling Audit" INFO

                $updatePolicyJson = $getPolicyDetails.Policy | ConvertTo-Json -Depth 10

                # Update policy
                $updatePolicy = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body ([System.Text.Encoding]::UTF8.GetBytes($updatePolicyJson)) # to handle special char

                Write-Log "$($policy.PolicyName): updated correctly - audit enabled." INFO
            } else {
                Write-Log "$($policy.PolicyName): Nothing to do, Policy Audit enabled." INFO
            }
        } else {
            Write-Log "$($policy.PolicyName): Policy Action 'Allow' not in scope." WARN
        }
        $policyCounter++
    }
}

if ($RemoveDuplicatedPolicy) {

    $policiesSearchFilter = @{
        "filter" = "PolicyType EQ ADV_WIN"
    } | ConvertTo-Json

    $policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter
    
    Write-Log "Found $($policySearch.FilteredCount) of a total $($policySearch.TotalCount) policies" INFO

    # Initialize hashtables
    $policiesWithoutSuffix = @{}
    $policiesWithSuffix = @{}

    # Iterate through the policies
    foreach ($policy in $policySearch.Policies) {
        $policyName = $policy.PolicyName
        $policyID = $policy.PolicyID

        # Check if the policy name ends with " (\d+)"
        if ($policyName -match " \(\d+\)$") {
            # Add to the hashtable for policies with suffix
            if (-not $policiesWithSuffix.ContainsKey($policyName)) {
                $policiesWithSuffix[$policyName] = @()
            }
            $policiesWithSuffix[$policyName] += $policyID
        } else {
            # Add to the hashtable for policies without suffix
            if (-not $policiesWithoutSuffix.ContainsKey($policyName)) {
                $policiesWithoutSuffix[$policyName] = @()
            }
            $policiesWithoutSuffix[$policyName] += $policyID
        }
    }

    $counter

    # Process policies in PoliciesWithSuffix and search in PoliciesWithoutSuffix
    foreach ($policyNameWithSuffix in $policiesWithSuffix.Keys) {
        # Remove the suffix " (number)" to get the base policy name
        $basePolicyName = $policyNameWithSuffix -replace " \(\d+\)$", ""

        # Check if the base policy name exists in PoliciesWithoutSuffix
        if ($policiesWithoutSuffix.ContainsKey($basePolicyName)) {
            $policyIdsWithSuffix = $policiesWithSuffix[$policyNameWithSuffix]
            $policyIdsWithoutSuffix = $policiesWithoutSuffix[$basePolicyName]

            # Process the matching policies (example: just output the details)
            Write-Log "$counter/$($policiesWithSuffix.Count) Found matching policy: $basePolicyName -> ID: $($policyIdsWithoutSuffix))" INFO
            Write-Log "  Duplicated Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            Write-Log "  Removing Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policyIdsWithSuffix)" -Method 'DELETE' -Headers $sessionHeader
            Write-Log "  Removed Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            
            # Additional processing can be done here if needed
        } else {
            Write-Log "$policyNameWithSuffix not duplicated" INFO
        }

        $counter++
        
    }
}

if ($RemoveImportedFlag) {

    Write-Log "Processing Policies..." INFO
    
    # Policies Search Filter
    $policiesSearchFilter = @{
        "filter" = "PolicyName CONTAINS [IMPORTED]"
    } | ConvertTo-Json

    $policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter
    
    Write-Log "Found $($policySearch.FilteredCount) of a total $($policySearch.TotalCount) policies imported" INFO

    $counter = 1
    
    foreach ($policy in $policySearch.Policies) {
               
        if ($policy.PolicyName -match "^\[IMPORTED\] .*$") {
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Getting policy details..." INFO
            $getPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader

            $getPolicyDetails.Policy.Name = $policy.PolicyName -replace "^\[IMPORTED\] ", ""
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Renamed as $($getPolicyDetails.Policy.Name)" INFO

            $updatePolicyJson = $getPolicyDetails.Policy | ConvertTo-Json -Depth 10
 
            $updatePolicy = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body ([System.Text.Encoding]::UTF8.GetBytes($updatePolicyJson)) # to handle special char
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Policy updated succesfully. New policy name is: $($updatePolicy.Name)" INFO
            
            $counter++
        }
    }

    Write-Log "... Done Policies" INFO

    Write-Log "Processing Application Groups..." INFO

    # Application Group Search Filter
    $appGroupSearchFilter = @{
        "filter" = "PolicyName CONTAINS [IMPORTED]"
    } | ConvertTo-Json

    $appGroupSearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $appGroupSearchFilter
    
    Write-Log "Found $($appGroupSearch.FilteredCount) of a total $($appGroupSearch.TotalCount) application groups imported" INFO

    $counter = 1
    
    foreach ($appGroup in $appGroupSearch.Policies) {
               
        if ($appGroup.PolicyName -match "^\[IMPORTED\] .*$") {
            Write-Log "$counter/$($appGroupSearch.FilteredCount) - $($appGroup.PolicyName): Getting application group details..." INFO
            $getAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/$($appGroup.PolicyId)" -Method 'GET' -Headers $sessionHeader

            $getAppGroupDetails.Policy.Name = $appGroup.PolicyName -replace "^\[IMPORTED\] ", ""
            Write-Log "$counter/$($appGroupSearch.FilteredCount) - $($appGroup.PolicyName): Renamed as $($getAppGroupDetails.Policy.Name)" INFO

            $updateAppGroupJson = $getAppGroupDetails.Policy | ConvertTo-Json -Depth 10
 
            $updateAppGroup = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/$($appGroup.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body ([System.Text.Encoding]::UTF8.GetBytes($updateAppGroupJson)) # to handle special char
            Write-Log "$counter/$($appGroupSearch.FilteredCount) - $($appGroup.PolicyName): Applcation Group updated succesfully. New application group name is: $($updateAppGroup.Name)" INFO
            
            $counter++
        }
    }
    Write-Log "... Done Application Groups..." INFO
}

if ($DisablePolicies) {
    if (-not (Test-Path $PoliciesFile)) {
        Write-Log "File '$PoliciesFile' not found. Skipping." ERROR        Return
    }
    
    Write-Log "Fetching current policies list from EPM Console..." INFO
    $policiesSearchFilter = @{
        "filter" = "PolicyType EQ ADV_WIN"
    }
    $policySearch = Get-EPMPolicies -policyFilter $policiesSearchFilter

    $PoliciesLookup = @{}
    foreach ($policy in $policySearch.Policies){
        if ($null -eq $policy.PolicyName) { continue }
        $PoliciesLookup[$policy.PolicyName] = [PSCustomObject]@{
            Id       = $policy.PolicyId
            IsActive = [bool]$policy.IsActive # Cast to bool to ensure type safety
        }
    }

    Write-Log "Importing data from $PoliciesFile..." INFO
    $PoliciesTotalCount = (Get-Content $PoliciesFile | Measure-Object).Count - 1
    
    $Counter = 1
    
    Write-Log "Processing $($PoliciesTotalCount) rows from $PoliciesFile..." INFO
    Import-Csv -Path $PoliciesFile | ForEach-Object {
        Write-Log "$counter/$PoliciesTotalCount Processing Policy: '$($_.PolicyName)'" INFO
        if ($PoliciesLookup.ContainsKey($_.PolicyName)) {
            
            $PolicyLookup = $PoliciesLookup[$_.PolicyName]
            if ($PolicyLookup.IsActive -eq $true) {
                Write-Log "Policy '$($_.PolicyName)' found and active." INFO
                
                $URIpDetails = "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($PolicyLookup.Id)"
                $getPolicyDetailsParam = @{
                    Uri = $URIpDetails
                    Method = 'GET'
                    Headers = $sessionHeader
                }
                $getPolicyDetails = Invoke-EPMRestMethod @getPolicyDetailsParam

                $getPolicyDetails.Policy.IsActive = $false
                Write-Log "$($_.PolicyName): Disabling Policy" INFO

                $updatePolicyJson = $getPolicyDetails.Policy | ConvertTo-Json -Depth 10

                # Update policy
                $updatePolicyParam = @{
                    Uri = $URIpDetails
                    Method = 'PUT'
                    Headers = $sessionHeader
                    Body = ([System.Text.Encoding]::UTF8.GetBytes($updatePolicyJson)) # to handle special char
                }
                $null = Invoke-EPMRestMethod @updatePolicyParam
                Write-Log "$($_.PolicyName): Successfully disabled." INFO
            } else {
                Write-Log "$($_.PolicyName): Already disabled in EPM. Skipping." INFO
            }
        } else {
            Write-Log "$($_.PolicyName): Not found in EPM search results." WARN
        }
        $Counter++
    } 
}
