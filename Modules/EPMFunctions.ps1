<#
.SYNOPSIS
    

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMBaseFunc.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 3
    Created: 05/2023
    Last Modified: 07/2026

    # 3.0: Adding the ISPSS Auth
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage="ISPSS Address")]
    [string]$ISPSS,
    
    #[Parameter(HelpMessage="Please enter valid ISPSS OATH alias")]
    #[string]$AppAlias,
    
    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder 
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

function Initialize-Log {
<#
.SYNOPSIS
    Initializes the log file path and ensures the log folder exists.

.DESCRIPTION
    This function handles the setup for script logging. It determines the log folder,
    creates it if necessary, and constructs a unique log file path based on the script name and timestamp.

.PARAMETER LogFolder
    The path to the desired log folder. If not provided, a 'log' subfolder in the script's directory is used.

.OUTPUTS
    System.String. The full path to the created log file.
#>
    param (
        [Parameter(HelpMessage = "Specify the log file path")]
        [string]$LogFolder
    )

    if (-not $PSBoundParameters.ContainsKey('LogFolder') -or [string]::IsNullOrWhiteSpace($LogFolder)) {
        $scriptDirectory = $MyInvocation.PSScriptRoot
        $LogFolder = Join-Path $scriptDirectory "log"
    }

    if (-not (Test-Path -Path $LogFolder -PathType Container)) {
        New-Item -Path $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    #$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptName)
    $logFileName = "$timestamp`_$scriptName.log"
    
    $logFilePath = Join-Path $LogFolder $logFileName
    return $logFilePath
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


### Begin Script ###
$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path -leaf $MyInvocation.MyCommand.Path))
## Prepare log if needed
if ($log) {
    $LogFilePath = Initialize-Log -LogFolder $LogFolder
    Write-Log "Logging enabled. File: $LogFilePath" INFO
}

Write-Box "$ScriptName"

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"
if ($null -eq $credential) {
    Write-Log "Failed to get credentials..." ERROR
    exit
}

# Authenticate
if (-not $ISPSS){
#if (-not $SubDomain -and -not $AppAlias) {
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

Write-Log $login.managerURL INFO
Write-Log $set.SetName INFO
Write-Log $set.SetId INFO

<#
Write-Log "This is an INFO" INFO
Write-Log "This is a WARNING" WARN
Write-Log "This is an ERROR" ERROR
Write-Log "This is an INFO" INFO -ForegroundColor DarkCyan
#>

#Example Request 

# Test GetPolicies
$i = 1
while ($true) {
    $policies = Get-EPMPolicies -limit 50
    $policies
    Write-Log $i INFO
    $i++
}

# Test GetEndpoints
#$endpoints = Get-EPMEndpoints -limit 2
#$endpoints

# Test GetComputers
#$computers = Get-EPMComputers -limit 2
#$computers


# Wrong Body
#$policyFilter = @{
#    "filter" = "Active EQ true AND Action IN 3,4 AND PolicyType EQ ADV_WIN"
#}  | ConvertTo-Json
#
#Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policyFilter


#$retryCount = 0
#do {
    # All computers
#    $getComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers" -Method 'GET' -Headers $sessionHeader
    #$getComputerList | ConvertTo-Json
#    Write-Log $getComputerList INFO
#    $retryCount++
#} while ($retryCount -lt 20)

# Disconnected Computers
#$URLquery = "?`$filter=Status eq 'Disconnected'"
#$getDisconnectedComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers$URLQuery" -Method 'GET' -Headers $sessionHeader
#$getDisconnectedComputerList | ConvertTo-Json

#$getComputerList = Get-EPMComputers

#$OutputPath = "EPM_Computers_List.csv"

# Input is assumed to be the array property of the API result
#$ComputersArray = $getComputerList.Computers

# 1. Pipeline the objects directly to the export cmdlet.
#$ComputersArray | Export-Csv -Path $OutputPath -NoTypeInformation

#Write-Host "Successfully exported $($ComputersArray.Count) computers to $OutputPath" -ForegroundColor Green