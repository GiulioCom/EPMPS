<#
.SYNOPSIS
    Removes EPM Agent Policies via REST API.

.DESCRIPTION
    Connects to the EPM console to delete either a specific list of policies
    provided via CSV, or all custom policies within a specified Set.

.PARAMETER username
    The EPM username used for authentication (e.g., admin@cyberark.com).

.PARAMETER setName
    The specific EPM Set Name where the endpoints reside.

.PARAMETER tenant
    The EPM tenant/region prefix (e.g., 'eu', 'na', 'uk').

.PARAMETER EndpointReportCSV
    The full path to the CSV report containing the 'Agent Id' and 'Computer' columns.

.NOTES
    Author: Giulio Compagnone
    Company: PaloAltoNetworks
    Version: 0.1 - POC
    Date: 05/2026

.EXAMPLE
    .\Remove-AgentPolicy.ps1 -Username "user@domain" -SetName "MySet" -Tenant "eu" -CSV "C:\Reports\AgentsList.csv"
.EXAMPLE
    .\Remove-AgentPolicy.ps1 -Username "user@domain" -SetName "MySet" -Tenant "eu" -AllCustom
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ByCSV')]
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

    [Parameter(Mandatory = $true, ParameterSetName = 'ByCSV', HelpMessage = "Path to the CSV file containing policies to remove")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$CSV,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByAllCustom', HelpMessage = "Remove ALL custom policies in the specified Set")]
    [switch]$AllCustom
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
            return Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
        }
        catch {
            $ErrorDetailsMessage = $null

            # Extract API error details if available
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try {
                    $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - Failed to parse error message as JSON. Raw message: $($_.ErrorDetails.Message)" ERROR
                    throw $_.ErrorDetails.Message
                }
            }

            if ($null -eq $ErrorDetailsMessage) {
                Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - $URI - HTTP Error: $($_.Exception.Message)" ERROR

                if ($_.Exception.Response) {
                    $responseStream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    $errorBody = $reader.ReadToEnd()
                    $reader.Close()

                    if (-not [string]::IsNullOrWhiteSpace($errorBody)) {
                        Write-Log "Server Error Detail: $errorBody" ERROR
                    }
                }
                throw $_.Exception.Message
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
                    throw "ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                } elseif ($ErrorDetailsMessage.ErrorCode -eq "EPM000012E") {
                # Handle Error EPM000012E - "ErrorMessage: EPM cannot identify the following target computers that were previously selected."
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    return
                }
                else {
                # Log any other error
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    throw "ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
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

Function Get-AgentConf {
<#
.SYNOPSIS
    Retrieves a list of Agent Policies, handling pagination automatically.

.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get agent policies.
    It automatically manages pagination by making multiple API calls if the total number
    of policies exceeds the API's maximum limit (1000). The function merges all
    policies into a single PSCustomObject for easy management.

.PARAMETER limit
    The maximum number of policies to retrieve per API call. The default is 1000,
    which is the maximum allowed by the CyberArk EPM API.

.EXAMPLE
    Get-AgentPolicies -limit 500

.OUTPUTS
    This function returns an object containing the merged policies and metadata.
    The object has the following properties:
        - Policies: An array of all policy objects.
        - ActiveCount: number of active policies,
        - TotalCount: Total policies available,
        - FilteredCount: Total policies returned

.NOTES
    This function requires a valid session header and manager URL to be accessible
    in the execution context. It uses Invoke-EPMRestMethod.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage="Base URI for the EPM Set")]
        [ValidateNotNullOrEmpty()]
        [string]$URI,

        [Parameter(Mandatory = $true, HelpMessage="Authorization headers")]
        [ValidateNotNull()]
        [hashtable]$SessionHeader,

        [Parameter(HelpMessage="Maximum items per request")]
        [ValidateRange(1, 1000)]
        [int]$Limit = 1000,

        [Parameter(HelpMessage="Filter string for the search body")]
        [string]$Filter = ""
    )    

    $policyList = [System.Collections.Generic.List[object]]::new()
    $activeCount = 0
    $totalCount = 0
    $filteredCount = 0

    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        $bodyObject = @{ filter = $Filter }
        $jsonBody = $bodyObject | ConvertTo-Json -Compress -Depth 10
    } else {
        $jsonBody = "{}"
    }
    
    $offset = 0             # Offset
    $total = $offset + 1    # Define the total, setup as offset + 1 to start the while cycle

    while ($offset -lt $total) {
        
        $getAgentConfParam = @{
            URI = "$URI/Policies/AgentConfiguration/Search?offset=$offset&limit=$limit"
            Method = 'POST'
            Headers = $sessionHeader
            Body = $jsonBody
        }
    
        $getAgentConf = Invoke-EPMRestMethod @getAgentConfParam
    
        if (-not $getAgentConf -or -not $getAgentConf.Policies) {
            Write-Log "No policies returned or unexpected payload structure at offset $offset." WARN
            break
        }
        
        $policyList.AddRange($getAgentConf.Policies)

        $activeCount   = $getAgentConf.ActiveCount
        $totalCount    = $getAgentConf.TotalCount
        $filteredCount = $getAgentConf.FilteredCount

        $total = $filteredCount
        $offset += $getAgentConf.Policies.Count

        # Manage 0 results
        if ($total -eq 0) { 
            break
        }
        
        # Progress Bar
        $Percent = [math]::Round(($offset / $total) * 100)
        if ($Percent -gt 100) { $Percent = 100 }
        Write-Progress -Activity "Retrieving Agent Config: $($total) total" -Status "Retrieved: $offset Agent Config" -PercentComplete $Percent
        
    }
    Write-Progress -Activity "Retrieving Agent Config $($total) total"  -Status "Completed: Successfully retrieved $($mergeAgentConf.filteredCount) Agent Config" -PercentComplete 100 -Completed
    
    return [PSCustomObject]@{
        Policies      = $policyList.ToArray()
        ActiveCount   = $activeCount
        TotalCount    = $totalCount
        FilteredCount = $filteredCount
    }
}


# Logging setup
#$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

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

# General URI
$URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"

$AgentConfIdsToRemove = [System.Collections.Generic.List[string]]::new()

$agentConfs = Get-AgentConf -URI $URI -SessionHeader $sessionHeader

switch ($PSCmdlet.ParameterSetName) {
    
    'ByCSV' {
        Write-Log -Message "Starting deletion via CSV list: $CSV" INFO
        
        Import-Csv -Path $CSV | ForEach-Object {

            foreach ($agentConf in $agentConfs.Policies){
                if ($agentConf.Name -eq $_) {
                    $AgentConfIdsToRemove.Add($agentConf.PolicyId)
                }
            }
        }
    }

    'ByAllCustom' {
        Write-Log "Starting deletion of ALL custom policies in Set: $SetName" INFO
        
        foreach ($agentConf in $agentConfs.Policies){
            # Exude the General Config. Generaconfig Id is the same as the Tenant SET ID
            if ($agentConf.PolicyId -ne $set.setId) {
                $AgentConfIdsToRemove.Add($agentConf.PolicyId)
            }
        }
    }
}


if ($PSCmdlet.ShouldProcess("EPM Policy ID: $targetPolicyId", "DELETE REST API Call")) {
    
    foreach ($Ids in $AgentConfIdsToRemove){
        $getAgentConf = Invoke-EPMRestMethod "$URI/Policies/AgentConfiguration/$Ids" -Method "Delete" -Headers $sessionHeader
    }
}