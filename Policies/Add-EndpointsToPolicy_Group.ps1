<#
.SYNOPSIS
    Adds computers to CyberArk EPM policies based on a CSV file.

.DESCRIPTION
    This script automates the process of assigning EPM policies to specific computers. It reads a CSV file
    that maps computer names to policy names. For each computer in the file, it verifies the existence of
    both the computer and the specified policies within a given EPM set and tenant. If a valid policy
    is found, the script updates the policy to include the computer. The script also handles
    user-based policies and tracks managed computers to avoid re-processing.

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER policyFile
    The full path to the input CSV file. The file must contain two columns:
        1. The Computer Name (e.g., WIN10X64-1).
        2. A semicolon-separated list of Policy Names to be applied.
    
    Example CSV format:
    WIN10X64-1,Script;Shell;PM-Allow Edit Enviroment Variable
    WIN11-1,Script

.EXAMPLE
    .\EPMAddComputertoPolicy_Group.ps1 -username "admin@epm.com" -setName "Default Set" -tenant "eu" -CsvPath "C:\temp\policy_assignments.csv"

.NOTES
    File: EPMAddComputertoPolicy.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 2
    Created: 07/2023
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$CsvPath
)

# Function to log messages to console and file
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
        [hashtable]$Headers = @{}
    )

    $MaxRetries = 3
    $RetryDelay = 120 # Default value, in case of the returned message doesn't contain the limit info
    $retryCount = 0

    $hErrorMsg = "API call failed at line {0}" -f $MyInvocation.ScriptLineNumber

    while ($retryCount -lt $MaxRetries) {
        try {
            return Invoke-RestMethod -Uri $URI -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
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
                $errorObject = @($ErrorDetailsMessage)[0]

                if ($null -ne $errorObject.ErrorCode) {
                    $EPMErrorCode = $errorObject.ErrorCode
                }
                if ($null -ne $errorObject.ErrorMessage) {
                    $EPMErrorMsg = $errorObject.ErrorMessage
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
Connects to the EPM (Endponint Priviled Management) using the provided credentials and tenant information.

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
    } | ConvertTo-Json -Compress

    $authHeaders = @{
        "Content-Type" = "application/json"
    }

    try {
        $URI = 'https://{0}.epm.cyberark.com/EPM/API/Auth/EPM/Logon' -f $epmTenant
        $response = Invoke-EPMRestMethod -URI $URI -Method 'POST' -Headers $authHeaders -Body $authBody

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
    Connects to CyberArk EPM using the ISPSS OIDC/OAuth portal.
.DESCRIPTION
    Authenticates against CyberArk Identity ISPSS via client_credentials, retrieves an access token,
    and queries the tenant's base manager URL. Keeps credentials secure in memory using byte arrays.
.PARAMETER credential
    The PSCredential object representing the client ID (Username) and client secret (Password).
.PARAMETER epmTenant
    The EPM tenant name (e.g., eu, uk).
.PARAMETER SubDomain
    The ISPSS identity portal subdomain.
.PARAMETER AppAlias
    The unique OAuth application alias configuration name.
.OUTPUTS
    [PSCustomObject] containing 'managerURL' (string) and 'auth' (string).
#>
function Connect-EPM-ISPSS {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscredential]$credential,

        [Parameter(Mandatory = $true)]
        [string]$epmTenant,

        [Parameter(Mandatory = $true)]
        [string]$OATH2
    )

    $access_token = ""
    $tenantUrl = ""
    
    # Login ISPSS
    try {

        $rawCreds = "{0}:{1}" -f $credential.UserName, $credential.GetNetworkCredential().Password
        $base64   = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawCreds))
        
        # Clean up the clear text variable
        $rawCreds = $null
        
        $headers = @{ "Authorization" = "Basic $base64" }
        $body    = @{ grant_type = "client_credentials" }

        $login = Invoke-RestMethod -Uri $OATH2 -Method Post -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"

        # Ensure the response contains the expected fields
        if (-not $login -or -not $login.access_token -or -not $login.token_type -or -not $login.expires_in) {
            $msg = "EPM authentication failed on {0}: Missing expected response fields." -f $OATH2
            Write-Log $msg ERROR
            throw $msg
        }

        $access_token = $login.access_token

    }
    catch {
        $msg = "Failed to connect to EPM tenant: {0}. Error: {1}" -f $url, $_.Exception.Message
        Write-Log $msg ERROR
        throw $msg
    }

    # Get the tenant URL
    try {
        $url = "https://api-{0}.epm.cyberark.cloud/epm/api/accounts/tenanturl" -f $epmTenant
        $headers = @{ "Authorization" = "Bearer $access_token" }

        $tenant = Invoke-RestMethod -Uri $url -Method GET -Headers $headers

        # Ensure the response contains the expected fields
        if (-not $tenant -or -not $tenant.tenantUrl) {
            $msg = "Failed get the tenant URL on {0}: Missing expected response fields." -f $url
            Write-Log $msg ERROR
            throw $msg
        }

        $tenantUrl = $tenant.tenantUrl

    }
    catch {
        $msg = "Failed to connect to EPM tenant: {0}. Error: {1}" -f $url, $_.Exception.Message
        Write-Log $msg ERROR
        throw $msg
    }

    # Return a custom object with connection information
    return [PSCustomObject]@{
        managerURL = $tenantUrl
        auth       = $access_token
    }
}

function Get-EPMSetID {
    <#
    .SYNOPSIS
        Retrieves the ID and name of an EPM set based on the provided parameters.
    .DESCRIPTION
        Interacts with the EPM API to retrieve sets. If a name is provided, it extracts it cleanly.
        Otherwise, it provides an interactive prompt for the user.
    .PARAMETER managerURL
        The base URL of the EPM manager.
    .PARAMETER Headers
        The hashtable containing the Authorization token.
    .PARAMETER setName
        The exact name of the EPM set to retrieve.
    .OUTPUTS
        [PSCustomObject] containing 'setId' and 'setName'.
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
        $uri = "{0}/EPM/API/Sets" -f $managerURL.TrimEnd('/')
        $setsResponse = Invoke-EPMRestMethod -URI $uri -Method 'GET' -Headers $Headers
        $setsArray = @($setsResponse.Sets)

        if (-not $setsArray -or $setsArray.Count -eq 0) {
            $msg = "No sets available. Verify the user permission."
            Write-Log $msg ERROR
            throw $msg
        }
    }
    catch {
        $msg = "Failed to retrieve EPM Sets. Error: {0}" -f $_.Exception.Message
        Write-Log $msg ERROR
        throw $msg
    }

    # If setName is provided, search for it directly
    if (-not [string]::IsNullOrWhiteSpace($setName)) {
        $selectedSet = $setsArray.Where({ $_.Name -eq $setName }, 'First', 1)

        if ($selectedSet) {
            return [PSCustomObject]@{
                setId   = $selectedSet[0].Id
                setName = $selectedSet[0].Name
            }
        } else {
            $msg = "Invalid Set Name: '{0}' not found in EPM." -f $setName
            Write-Log $msg ERROR
            throw $msg
        }
    }

    Write-Box "Available Sets:"

    for ($i = 0; $i -lt $setsArray.Count; $i++) {
        Write-Log "$($i + 1). $($setsArray[$i].Name)" INFO DarkCyan
    }

    # Prompt user for input with max retries
    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        $rawInput = Read-Host "Enter the number of the set you want to choose"
        $chosenSetNum = 0

        if ([int]::TryParse($rawInput, [ref]$chosenSetNum)) {
            if ($chosenSetNum -ge 1 -and $chosenSetNum -le $setsArray.Count) {
                $chosenSet = $setsArray[$chosenSetNum - 1]
                return [PSCustomObject]@{
                    setId   = $chosenSet.Id
                    setName = $chosenSet.Name
                }
            } else {
                $msg = "Invalid selection. Please enter a number between 1 and {0}." -f $setsArray.Count
                Write-Log $msg ERROR
            }
        } else {
            Write-Log "Invalid input. Please enter a valid numerical digit." ERROR
        }
    }

    $msg = "Maximum attempts reached. Exiting set selection."
    Write-Log $msg ERROR
    throw "Maximum attempts reached. Exiting set selection."
}

Function Get-Endpoints {
    <#
    .SYNOPSIS
        Retrieves a list of EPM Computers from a CyberArk EPM server, handling pagination automatically.

    .DESCRIPTION
        This function acts as a wrapper for the CyberArk EPM REST API to get computers.
        It automatically manages pagination by making multiple API calls if the total number
        of computers exceeds the API limit. The results are merged efficiently into a single object.

    .PARAMETER URI
        The base URI of the EPM server.
    .PARAMETER Headers
        The authentication headers.
    .PARAMETER limit
        The maximum number of computers to retrieve per API call. Default: 1000.
    .PARAMETER filter
        The search string to filter endpoints.

    .EXAMPLE
        $allEndpoints = Get-Endpoints -RootURI $uri -Headers $auth -limit 1000

    .OUTPUTS
        This function returns an object containing the merged computers and metadata.
        The object has the following properties:
            - endpoints: An array of all policy objects.
            - filteredCount: The total number of endpoints  based on the filter.
            - returnedCount: The returned number of endpoints based on limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$URI,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
    
        [int]$limit = 1000,     #Set limit to the max size if not declared
        [string]$filter         #Set the search body
    )

    $endpointList = [System.Collections.Generic.List[object]]::new()
    $filteredCount = 0
    $returnedCountTotal = 0

    $bodyHashtable = @{}
    if ((-not [string]::IsNullOrWhiteSpace($filter))) {
        $bodyHashtable.filter = $filter
    }
    $bodyJSON = $bodyHashtable | ConvertTo-Json -Compress

    $offset = 0

    do {
        $URI = '{0}/Endpoints/search?offset={1}&limit={2}' -f $URI.TrimEnd('/'), $offset, $limit
        $response = Invoke-EPMRestMethod -Uri $URI -Method 'POST' -Headers $Headers -Body $bodyJSON
        
        if ($null -eq $response -or $null -eq $response.endpoints) {
            Write-Log "API returned an empty or malformed response at offset $offset." WARN
            break
        }
        
        $endpointList.AddRange($response.endpoints)

        $filteredCount = $response.filteredCount
        $returnedCountTotal += $response.returnedCount
        $offset += $response.returnedCount

    } while (
        ($offset -lt $filteredCount) -and 
        ($response.returnedCount -gt 0) # LOGIC: Failsafe to prevent an infinite loop if the API stalls and returns 0 items
    )
    
    return [PSCustomObject]@{
        endpoints     = $endpointList.ToArray()
        filteredCount = $filteredCount
        returnedCount = $returnedCountTotal
    }
}

Function Get-Policies {
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
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$URI,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        
        [int]$limit = 1000,             # Set limit to the max size if not declared
        [string]$sortBy = "Updated",
        [string]$sortDir = "desc",
        [string]$filter
    )

    $policyList = [System.Collections.Generic.List[object]]::new()
    $activeCount = 0
    $totalCount = 0
    $filteredCount = 0

    $bodyHashtable = @{}
    if ((-not [string]::IsNullOrWhiteSpace($filter))) {
        $bodyHashtable.filter = $filter
    }
    $bodyJSON = $bodyHashtable | ConvertTo-Json -Compress

    $sort = 'sortBy={0}&sortDir={1}' -f $sortBy, $sortDir

    $offset = 0             # Offset

    do {
        $URI = '{0}/Policies/Server/Search?offset={1}&limit={2}&{3}' -f $URI.TrimEnd('/'), $offset, $limit, $sort
        $response = Invoke-EPMRestMethod -Uri $URI -Method 'POST' -Headers $Headers -Body $bodyJSON
        
        $policyList.AddRange($response.Policies)
        $activeCount = $response.ActiveCount       # Update the ActiveCount
        $totalCount = $response.TotalCount         # Update the TotalCount
        $filteredCount = $response.FilteredCount   # Update the FilteredCount

        #$total = $response.FilteredCount                         # Update the total with the real total
        $offset += $response.Policies.Count

    } while (
        ($offset -lt $filteredCount) #-and 
        #($response.returnedCount -gt 0) # LOGIC: Failsafe to prevent an infinite loop if the API stalls and returns 0 items
    )

    return [PSCustomObject]@{
        Policies = $policyList.ToArray()
        ActiveCount = $activeCount
        TotalCount = $totalCount
        FilteredCount = $filteredCount
    }
   
}

function Add-EndpointToPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$URI,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointId,

        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[A-Za-z0-9\-]{1,15}$')]
        [string]$EndpointName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId
    )
        
    $URI = '{0}/Policies/Server/{1}' -f $URI.TrimEnd('/'), $PolicyId
    
    $policyDetails = Invoke-EPMRestMethod -Uri $URI -Method 'GET' -Headers $Headers
    $policy = $policyDetails.Policy

    # Configure the policy for specific device
    $policy.IsAppliedToAllComputers=$False

    # Enable the policy
    $policy.IsActive=$True

    ## Add the computer in the policy definition
    if ($policy.Executors.Name -contains $EndpointName) {
        Write-Log "Endpoint '$($EndpointName)' already exists in the policy '$($policy.Name)'. Continue to the next..." WARN
    } else {
        Write-Log "Adding Endpoint '$($EndpointName)' to '$($policy.Name)'." INFO

        # Define the executor
        $newExecutor = [PSCustomObject]@{
            "Id"           = $EndpointId
            "Name"         = $EndpointName
            "IsIncluded"   = $true
            "ExecutorType" = 1
        }

        # Add the Computer in the policy
        $executorList = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $policy.Executors) {
            $executorList.AddRange($policy.Executors)
        }
        $executorList.Add($newExecutor)
        $policy.Executors = $executorList.ToArray()

        # Upload the policy
        $newPolicyJSON = $policy | ConvertTo-Json -Depth 10 -Compress
        $updatePolicy = Invoke-EPMRestMethod -Uri $URI -Method 'PUT' -Headers $Headers -Body $newPolicyJSON
        
        if ($null -ne $updatePolicy) {
            Write-Log "Policy '$($policy.Name)' updated." INFO
        } else {
            Write-Log "Error Updating Policy '$($policy.Name)'." ERROR
        }
    }
}

### Begin Script ###

## Prepare log folder and file
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
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
## Log file done

Write-Box "$scriptName"

# Request EPM Credentials
$sessionHeader = @{}

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"
if ($null -eq $credential) {
    Write-Log "Failed to get credentials..." ERROR
    exit
}

# Authenticate
if (-not $ISPSS){
    Write-Log "Legacy authetication..." INFO
    $login = Connect-EPM -credential $credential -epmTenant $tenant

    # Create a session header with the authorization token
    $sessionHeader = @{
        "Authorization" = "basic {0}" -f $login.auth
    }

} else {
    Write-Log "Modern authetication to $ISPSS ..." INFO
    $login = Connect-EPM-ISPSS -credential $credential -epmTenant $tenant -OATH2 $ISPSS

    $sessionHeader = @{
        "Authorization" = "Bearer {0}" -f $login.auth
    }
}
# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue

# EPM Connection:
$epmConnection = @{
    URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"
    Headers = $sessionHeader
}

# Keep track of the processed Endpoints to reduce the request
#$endpointsProcFile = "EndpointsProcessed.txt"
#$endpointsProc = @()

#if (Test-Path -Path $endpointsProcFile -PathType Leaf) {
#    Write-Log "Found Endpoints processed file: $endpointsProcFile" INFO
    # Load the file content
#    $endpointsProc = Get-Content $endpointsProcFile
#} else {
#    Write-Log "Endpoints processed file '$endpointsProcFile' not found, create new one." WARN
#    Set-Content -Path $endpointsProcFile -Value $endpointsProc -Force
#}

Write-Log "Loading and validating CSV data into memory..." INFO

$requiresPolicy = $false
$requiresGroup = $false

# Global Cache
$cachePolicies = @{}
$cacheGroups = @{}

$CsvMap = @{}
$Headers = @('ComputerName', 'RecordType', 'ItemList')

Import-Csv -Path $CsvPath -Header $Headers | ForEach-Object {
    $compName = $_.ComputerName.Trim().ToUpper()
    
    if ($compName -notmatch '^[A-Z0-9\-]{1,15}$') {
        Write-Log "Invalid ComputerName skipped: $compName" WARN
        return
    }

    $type = $_.RecordType.Trim().ToLower()
    if ($type -notin @('policy', 'group')) {
        Write-Log "Invalid RecordType '$type' for $compName. Skipping." WARN
        return
    }

    $items = $_.ItemList.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)

    if (-not $CsvMap.ContainsKey($compName)) {
        $CsvMap[$compName] = [PSCustomObject]@{
            Policies = [System.Collections.Generic.List[string]]::new()
            Groups   = [System.Collections.Generic.List[string]]::new()
        }
    }

    if ($type -eq 'policy') {
        $CsvMap[$compName].Policies.AddRange($items)
        $requiresPolicy = $true
    } elseif ($type -eq 'group') {
        $CsvMap[$compName].Groups.AddRange($items)
        $requiresGroup = $true
    }
}

Write-Log "Fetching Endpoints validated in the CSV from the EPM Console..." INFO

# There is a limit to 10000 char for the filter string
# (https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/delete-endpoint.htm#Bodyparameters)

[string[]]$TargetComputers = $CsvMap.Keys
$MaxCharLimit = 10000

$CurrentBatch = [System.Collections.Generic.List[string]]::new()
$LiveEndpoints = [System.Collections.Generic.List[object]]::new()
$filterHeader = "name IN "
$currentLength = $filterHeader.Length

foreach ($comp in $TargetComputers) {
    $addedLength = $comp.Length + 1

    if (($currentLength + $addedLength) -gt $MaxCharLimit) {

        $endpointsList = [string]::Join(',', $CurrentBatch)
        $filterString = '{0}{1}' -f $filterHeader, $EndpointsList
        $batchResults = Get-Endpoints @epmConnection -filter $filterString
        if ($batchResults.returnedCount -ne 0) {
            $LiveEndpoints.AddRange($batchResults.endpoints)
        }
        
        # Reset the batch tracker for the next chunk
        $CurrentBatch.Clear()
        $currentLength = $filterHeader.Length
    }

    $CurrentBatch.Add($comp)
    $currentLength += $addedLength

}

# Process Last Batch - Less than 10000
if ($CurrentBatch.Count -gt 0) {
    
    $endpointsList = [string]::Join(',', $CurrentBatch)
    $filterString = 'name IN {0}' -f $EndpointsList
    $finalResults = Get-Endpoints @epmConnection -filter $filterString
    if ($finalResults.returnedCount -ne 0) {
        $LiveEndpoints.AddRange(@($finalResults.endpoints))
    }
}

if ($LiveEndpoints.Count -eq 0) {
    Write-Log "The Endpoints in the CSV are not in the EPM console yet. Exit." WARN
    Exit
}

Write-Log "Successfully retrieved $($LiveEndpoints.Count) endpoints." INFO

if ($requiresPolicy) {
    Write-Log "Fetching global policies into local cache..." INFO

    # Get the policies list
    # 11: Advanced Windows
    # 36: User Policy Set Security Permissions for File System and Registry Keys
    # 37: User Policy Set Security Permissions for Services
    # 38: User Policy Set Security Permissions for Removable Storage (USB, Optical Discs)

    $policiesFilter = "PolicyType IN 11,36,37,38"

    $LivePolicies = Get-Policies @epmConnection -filter $policiesFilter
    Write-Log "Successfully retrieved $($LivePolicies.Count) policies." INFO

    foreach ($policy in $LivePolicies.Policies) {
        $cachePolicies[$policy.PolicyName] = $policy.PolicyId
    }

    Write-Log "Successfully cached $($cachePolicies.Count) policies." INFO
}

if ($requiresGroup) {
    Write-Log "Fetching static groups into local cache..." INFO

    $URI = '{0}/Endpoints/groups/search' -f $epmConnection.URI.TrimEnd('/')
    $filterGroups = @{
        filter = "type EQ Static"
    } | ConvertTo-Json -Compress
    
    $LiveGroups = Invoke-EPMRestMethod -URI $URI -Headers $sessionHeader -Method 'POST' -Body $filterGroups
    
    foreach ($group in $LiveGroups) {
        $cacheGroups[$group.name] = $group.id
    }

    Write-Log "Successfully cached $($cacheGroups.Count) groups." INFO
}


Write-Log "Applying configurations..." INFO

foreach ($endpoint in $LiveEndpoints) {
    $EndpointName = $endpoint.Name.ToUpper()
    Write-Log "Processing Endpoint: $($EndpointName)" INFO
    
    $config = $CsvMap[$EndpointName]

    if ($null -eq $config) {
        Write-Log "Endpoint $EndpointName returned by API but not in CSV mapping. Skipping." WARN
        continue
    }
    
    foreach ($group in $config.Groups) {
        Write-Log "Adding $EndpointName to Group: $group" INFO
        
        $URI = '{0}/endpoints/Groups/{1}/members/{2}' -f $epmConnection.URI.TrimEnd('/'), $cacheGroups[$group], $endpoint.Id
        [void](Invoke-EPMRestMethod -URI $URI -Headers $sessionHeader -Method 'POST')
        Write-Log "'$EndpointName' added to '$group'" INFO
    }

    foreach ($policyName in $config.Policies) {
        $policyId = $cachePolicies[$policyName]
        if ($null -ne $policyId) {
            Write-Log "Applying $policyName ($policyId) to $EndpointName" INFO
            Add-EndpointToPolicy @epmConnection -EndpointId $endpoint.legacyId -EndpointName $endpoint.Name -PolicyId $policyId
        }
        else {
            Write-Log "Policy '$policyName' not found in the EPM Console." WARN
        }
    }
}





 <#   
    # Search the Computer Name in the CSV file
    if ($csvComputerNames.Contains($computerName)) {
        Write-Log "- '$($computerName)' in the CSV policy file." INFO
        # Check if the endpoint has been processed already by reading the file
        if ($endpointsProc -notcontains $computerName){
            Write-Log "- '$($computerName)' is not in the processed file." WARN

            # Identify the polcies list from the CSV file
            $csvPoliciesList = ($policyContent | Where-Object { $_.ComputerName -eq $computerName }).Policies -split ';' | ForEach-Object { $_.Trim() }
            foreach ($policy in $csvPoliciesList) {
                Write-Log "- Processing policy '$($policy)'" INFO

                # Check if the policy exist
                If ($null -eq $($retrievedPoliciesMap[$policy])) {
                    Write-Log "- '$($policy)' not available in set '$($set.SetName)'" ERROR
                    Continue
                }
                
 
                }

            }
            # Add the Endopoint in the tracker file
            Add-Content -Path $endpointsProcFile -Value $computerName
            Write-Log "- Tracker file $endpointsProcFile updated for '$($computerName)'." INFO
        } else {
            Write-Log "- Computer '$($computerName)' already processed (in file $endpointsProcFile). Continue to the next..." WARN
        }
    }
}
#>
