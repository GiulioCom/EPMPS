<#
.SYNOPSIS
    Synchronizes policies between CyberArk EPM Sets.    

.DESCRIPTION
    Sync-EpmSetPolicy securely authenticates to the EPM API and synchronizes
    policy definitions from a source SET to a destination SET. 
    The policies supported are the policies support by REstAPI at this moment:
    - Any type for Advanced Policy (Check for the limitation)
    - Application Groups
    - Agent Configuration (Check for the limitation)
    Not supported:
    - Default Policy
    - Custom Dialog
    - Custom Agent Config
    - Any policy applied to Endpoints or Group

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER SourceSetName
    Source EPM Set Name.

.PARAMETER DestSetName
    Destination EPM Set Name.

.NOTES
    File: Sync-EPMSetPolicy.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 2
    Created: 09/2024
    Last Modified: 09/2025
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage="ISPSS OATH2 Application Address")]
    [string]$OATH2,
    
    [Parameter(HelpMessage = "Enable logging to file")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(HelpMessage="EPM set name used as source")]
    [string]$SourceSetName,

    [Parameter(HelpMessage="EPM set name used as destination")]
    [string]$DestSetName
    
)

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

    if ($script:EnableLogging) {
        [System.IO.File]::AppendAllText($script:LogFilePath, "$logMessage`r`n")
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
        [uri]$URI,
        [string]$Method,
        [object]$Body = $null,
        [hashtable]$Headers
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

function Connect-EPM-ISPSS {
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
.PARAMETER OATH2
    OATH2 full address.
.OUTPUTS
    [PSCustomObject] containing 'managerURL' (string) and 'access_token' (string).
#>
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

        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        
        $rawCreds = "{0}:{1}" -f $credential.UserName, $plainPassword
        $base64   = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawCreds))
        
        # Clean up the password
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $plainPassword = $null
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
        $msg = "Failed to connect to EPM tenant: {0}. Error: {1}" -f $OATH2, $_.Exception.Message
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
        [uri]$managerURL,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$setName
    )

    # Retrieve list of sets
    try {
        #$uri = "{0}/EPM/API/Sets" -f $managerURL.TrimEnd('/')
        $URI = [System.Uri]::new($managerURL, "EPM/API/Sets/")
        
        $setsResponse = Invoke-EPMRestMethod -URI $URI -Method 'GET' -Headers $Headers
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

Function Get-AppGroups {
    <#
    .SYNOPSIS
        Retrieves a list of EPM Application Groups from a CyberArk EPM server, handling pagination automatically.

    .DESCRIPTION
        This function acts as a wrapper for the CyberArk EPM REST API to get Application Groups.
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

    .PARAMETER filter
        A string containing filter criteria for the policies. 
        Check Filter options: https://docs.cyberark.com/epm/latest/en/content/webservices/getappgroups.htm#Filteroptions

    .EXAMPLE
        Get-AppGroups -limit 500 -sortBy "Name"

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
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Scheme -eq 'https' })]
        [System.Uri]$RootUri,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Headers,
        
        [ValidateRange(1, 1000)]
        [int]$limit = 1000,
        
        [int]$offset = 0,

        [ValidateSet('Name','PolicyName','ServerPolicyName','Type','PolicyType','ServerPolicyType','IsActive','Active','Status','Action','OsType','Platform','Precedence','Order','Computers','Allcomputers','Executors','IsAppliedToAllComputers','Created','Updated','LastModified','ModifiedDate')]
        [string]$sortBy,
        
        [ValidateSet('asc','desc')]
        [string]$sortDir,
        
        [string]$filter
    )

    $policyList = [System.Collections.Generic.List[object]]::new()
    $activeCount = 0
    $totalCount = 0
    $filteredCount = 0

    # API Param
    $RequestParam = @{
        Method  = 'POST'
        Headers = $Headers
    }

    # Prepare Body Filter
    if (-not [string]::IsNullOrWhiteSpace($filter)) {
    
        $Payload = [pscustomobject]@{
            filter = $filter
        }
        $RequestParam.Body = ConvertTo-Json -InputObject $Payload -Compress
    }

    $baseEndpoint = [System.Uri]::new($RootUri, 'Policies/ApplicationGroups/Search')
    $uriBuilder = [System.UriBuilder]::new($baseEndpoint)

    do {
        # Prepare Query
        $QueryElements = [System.Collections.Generic.List[string]]::new()
        $QueryElements.Add("offset=$offset")
        $QueryElements.Add("limit=$limit")
        
        if (-not [string]::IsNullOrWhiteSpace($sortBy)) { $QueryElements.Add("sortBy=$sortBy") }
        if (-not [string]::IsNullOrWhiteSpace($sortDir)) { $QueryElements.Add("sortDir=$sortDir") }

        $uriBuilder.Query = [string]::Join('&', $QueryElements)
        $RequestParam.URI = $uriBuilder.Uri
        
        $response = Invoke-EPMRestMethod @RequestParam
        
        $returnedItemsCount = $response.Policies.Count

        if ($returnedItemsCount -eq 0) {
            Write-Log "API returned 0 items. Reached the true end of the dataset." DEBUG
            break 
        }        
        
        $policyList.AddRange($response.Policies)
        $activeCount = $response.ActiveCount       # Update the ActiveCount
        $totalCount = $response.TotalCount         # Update the TotalCount
        $filteredCount = $response.FilteredCount   # Update the FilteredCount

        $offset += $returnedItemsCount

    } while ($offset -lt $filteredCount)

    [PSCustomObject]@{
        Policies = $policyList.ToArray()
        ActiveCount = $activeCount
        TotalCount = $totalCount
        FilteredCount = $filteredCount
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

    .PARAMETER filter
        A string containing filter criteria for the policies. 
        Check Filter options: https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicies.htm#Filteroptions

    .EXAMPLE
        Get-EPMPolicies -limit 500 -sortBy "Name"

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
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Scheme -eq 'https' })]
        [System.Uri]$RootUri,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Headers,
        
        [ValidateRange(1, 1000)]
        [int]$limit = 1000,
        
        [int]$offset = 0,

        [ValidateSet('Name','PolicyName','ServerPolicyName','Type','PolicyType','ServerPolicyType','IsActive','Active','Status','Action','OsType','Platform','Precedence','Order','Computers','Allcomputers','Executors','IsAppliedToAllComputers','Created','Updated','LastModified','ModifiedDate')]
        [string]$sortBy,
        
        [ValidateSet('asc','desc')]
        [string]$sortDir,
        
        [string]$filter
    )

    $policyList = [System.Collections.Generic.List[object]]::new()
    $activeCount = 0
    $totalCount = 0
    $filteredCount = 0

    # API Param
    $RequestParam = @{
        Method  = 'POST'
        Headers = $Headers
    }

    # Prepare Body Filter
    if (-not [string]::IsNullOrWhiteSpace($filter)) {
    
        $Payload = [pscustomobject]@{
            filter = $filter
        }
        $RequestParam.Body = ConvertTo-Json -InputObject $Payload -Compress
    }

    $baseEndpoint = [System.Uri]::new($RootUri, 'Policies/Server/Search')
    $uriBuilder = [System.UriBuilder]::new($baseEndpoint)

    do {
        # Prepare Query
        $QueryElements = [System.Collections.Generic.List[string]]::new()
        $QueryElements.Add("offset=$offset")
        $QueryElements.Add("limit=$limit")
        
        if (-not [string]::IsNullOrWhiteSpace($sortBy)) { $QueryElements.Add("sortBy=$sortBy") }
        if (-not [string]::IsNullOrWhiteSpace($sortDir)) { $QueryElements.Add("sortDir=$sortDir") }

        $uriBuilder.Query = [string]::Join('&', $QueryElements)
        $RequestParam.URI = $uriBuilder.Uri
        
        $response = Invoke-EPMRestMethod @RequestParam
        
        $returnedItemsCount = $response.Policies.Count

        if ($returnedItemsCount -eq 0) {
            Write-Log "API returned 0 items. Reached the true end of the dataset." DEBUG
            break 
        }        
        
        $policyList.AddRange($response.Policies)
        $activeCount = $response.ActiveCount       # Update the ActiveCount
        $totalCount = $response.TotalCount         # Update the TotalCount
        $filteredCount = $response.FilteredCount   # Update the FilteredCount

        $offset += $returnedItemsCount

    } while ($offset -lt $filteredCount)

    [PSCustomObject]@{
        Policies = $policyList.ToArray()
        ActiveCount = $activeCount
        TotalCount = $totalCount
        FilteredCount = $filteredCount
    }
}

### Begin Script ###

## Prepare log folder and file
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

$script:EnableLogging = $Log.IsPresent
$script:LogFilePath   = $null

if ($script:EnableLogging) {
    if (-not $PSBoundParameters.ContainsKey('logFolder')) {
        # Default to a 'log' folder in the same directory as the script
        $LogFolder = Join-Path -Path $PSScriptRoot -ChildPath "log"
    }

    # Ensure the log folder exists
if (-not (Test-Path -Path $LogFolder -PathType Container)) {
        [void](New-Item -Path $LogFolder -ItemType Directory -Force)
    }

    # Create log file name based on timestamp and script name
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "${timestamp}_${scriptName}.log"
    
    $script:LogFilePath = Join-Path -Path $LogFolder -ChildPath $logFileName

    Write-Log "Logging enabled. Log file: $($script:LogFilePath)" INFO
}
## Log file done

Write-Box "$scriptName"

# Request EPM Credentials
#$sessionHeader = @{}

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"

if ($null -eq $credential) {
    Write-Log "Failed to get credentials..." ERROR
    exit
}

# Authentication
if (-not $OATH2){
    Write-Log "Legacy authetication..." INFO
    $login = Connect-EPM -credential $credential -epmTenant $tenant
    $AuthPrefix = "basic"    

} else {
    Write-Log "Modern authetication to $OATH2 ..." INFO
    $login = Connect-EPM-ISPSS -credential $credential -epmTenant $tenant -OATH2 $OATH2
    $AuthPrefix = "Bearer"
}

# Store the auth header
$sessionHeader = @{
    "Authorization" = "$AuthPrefix {0}" -f $login.auth
    "Content-Type"  = "application/json; charset=utf-8" # OUTBOUND (POST/PUT): Tells the API what format we are sending.
    "Accept"        = "application/json; charset=utf-8" # INBOUND (GET): Tells the API what format we expect to receive back.
}

# Define the root endpoint
$EPMBaseEndpoint = $login.managerURL
if (-not $EPMBaseEndpoint.EndsWith('/')) {
    $EPMBaseEndpoint += '/'
}

[System.Uri]$EPMBaseUri = $EPMBaseEndpoint

# Retrieve Source SetId
$SourceSet = Get-EPMSetID -managerURL $EPMBaseUri -Headers $sessionHeader -setName $SourceSetName
$SafeSourceSetId = [uri]::EscapeDataString($SourceSet.setId)

$SourceURI = [System.Uri]::new($EPMBaseUri, "EPM/API/Sets/$SafeSourceSetId/")

# Retrieve Detination SetId
$DestSet = Get-EPMSetID -managerURL $EPMBaseUri -Headers $sessionHeader -setName $DestSetName
$SafeDestSetId = [uri]::EscapeDataString($DestSet.setId)
$DestURI = [System.Uri]::new($EPMBaseUri, "EPM/API/Sets/$SafeDestSetId/")

# Define destination AppGroup name mapping and store the uploaded AppGroup name and ID needed to map policies to appgroupto. Reduce the number of restapi request
$DestAppGroupMap = [System.Collections.Generic.Dictionary[string, string]]::new()

$policyTypes = @{
    1 =	'Privilege Management Detect'
    2 = 'Application Control Detect'
    3 =	'Application Control Restrict'
    4 = 'Ransomware Protection Detect'
    5 = 'Ransomware Protection Restrict'
    6 =	'INT Detect'
    7 = 'INT Restrict'
    8 =	'INT Block'
    9 =	'Privilege Management Elevate'
    10 = 'Application Control Block'
    11 = 'Advanced Windows'
    12 = 'Advanced Linux'
    13 = 'Advanced Mac'
    14 = 'Application Group Win'
    15 = 'Application Group Linux'
    16 = 'Application Group Win'
    17 = 'Recommended Block Windows OS Applications'
    18 = 'Predefined App Groups Win'
    19 = 'Microsoft Windows Programs (Win Files)'
    20 = 'Developer Applications'
    21 = 'Authorized Applications (Ransomware)'
    22 = 'Credentials Rotation'
    23 = 'Trusted Install Package Windows'
    24 = 'Trusted Distributor Windows'
    25 = 'Trusted Updater Windows'
    26 = 'Trusted User/Group Windows'
    27 = 'Trusted Network Location Windows'
    28 = 'Trusted URL Windows'
    29 = 'Trusted Publisher Windows'
    30 = 'Trusted Product Windows'
    31 = 'Trusted Distributor Mac'
    32 = 'Trusted Publisher Mac'
    33 = 'Trusted Distributor Predefined Definition Win'
    34 = 'Trusted Updater Predefined Definition Win'
    35 = 'Trusted Distributor Predefined Definition Mac'
    36 = 'User Policy - Set Security Permissions for File System and Registry Keys'
    37 = 'User Policy - Set Security Permissions for Services'
    38 = 'User Policy - Set Security Permissions for Removable Storage (USB, Optical Discs)'
    39 = 'Collect UAC actions by Local Admin'
    40 = 'JIT Access and Elevation'
    41 = 'Deploy Script'
    42 = 'Execute Script'
    43 = 'Predefined App Groups Win'
    44 = 'Agent Configuration'
    46 = 'Remove Admin'
    47 = 'Deception'
    48 = 'Desktop Login'
    51 = 'IDP Bridging'
}

$AppGroupTypes = @{
    14 = 'Application Group Win'
    15 = 'Application Group Linux'
    16 = 'Application Group Mac'
    19 = 'Microsoft Windows Programs (Win Files)'
    21 = 'Authorized Applications (Ransomware)'
    33 = 'Trusted Distributor Predefined Definition Win'
    34 = 'Trusted Updater Predefined Definition Win'
    35 = 'Trusted Distributor Predefined Definition Mac'
    43 = 'Predefined App Groups Win'
}

Write-Box "Application Groups"

# Get Application Groups
<#
$appGroupsFilter = ConvertTo-Json @{
    filter = "PolicyGroupType EQ 8" # Application Group -> Custom Application Group
} -Compress

$SearchAppURI = [System.Uri]::new($SourceURI, "Policies/ApplicationGroups/Search/")

$appGroupList = Invoke-EPMRestMethod -Uri $SearchAppURI -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
#>

# Filter by 'Changeable Application Group' -> Custom Application Group, Predefined App Group
$SourceAppGroups = Get-AppGroups -RootUri $SourceURI -Headers $sessionHeader -filter 'PolicyGroupType EQ 15' 

foreach ($appGroup in $SourceAppGroups.Policies) {
    
    $AppGroupName = $appGroup.PolicyName
    $AppGroupId = $appGroup.PolicyId
    $AppGroupType = $appGroup.PolicyType

    Write-Log "Processing '$AppGroupName'..." INFO
    
    $AppGroupTypeName = $AppGroupTypes[$AppGroupType]

    if ($null -eq $AppGroupTypeName) {
        Write-Log "Application Group Type '$AppGroupName' is unknown (Type: '$AppGroupType'). Skipping." WARN
        continue
    }
    
    # Get Application Group Details
    Write-Log "Get $AppGroupName" INFO
    
    $SafeAppGroupId = [uri]::EscapeDataString($AppGroupId)
    $AppGroupDetailsURI = [System.Uri]::new($SourceURI, "Policies/ApplicationGroups/$SafeAppGroupId/")
    $AppGroupDetails = Invoke-EPMRestMethod -Uri $AppGroupDetailsURI -Method 'GET' -Headers $sessionHeader

    if ($AppGroupType -eq 43) {
        # Predefined windows group can't be created
        # Only updated
        Write-Log "Get $AppGroupName from the destination SET" INFO
        # Get the related policy in the new Tenant
        $DestAppGroups = Get-AppGroups -RootUri $DestURI -Headers $sessionHeader -filter "PolicyName CONTAINS $AppGroupName"
        if ($DestAppGroups.Policies.Count -eq 0 -or $DestAppGroups.Policies.Count -gt 1) {
            Write-Log "Application Group Name '$AppGroupName' not found in the destination SET. Skipping." WARN
            Continue
        }

        $DestAppGroupId = $DestAppGroups.Policies[0].PolicyId

        # Replace the current policy ID with the policy ID in the destination set
        $AppGroupDetails.Policy.Id = $DestAppGroupId
        $AppGroupDetailsJson = ConvertTo-Json -InputObject $AppGroupDetails.Policy -Depth 10 -Compress

        $SafeDestAppGroupId = [uri]::EscapeDataString($DestAppGroupId)
        $UpdateAppGroupDetailsURI = [System.Uri]::new($DestURI, "Policies/ApplicationGroups/$SafeDestAppGroupId")
        $UpdateAppGroupDetails = Invoke-EPMRestMethod -Uri $UpdateAppGroupDetailsURI -Method 'PUT' -Headers $sessionHeader -Body $AppGroupDetailsJson


    } else {
        # Managing support groups
        $AppGroupDetails.Policy.PSObject.Properties.Remove("Id")

        # Convert as JSON ready to be uploaded
        $AppGroupDetailsJson = ConvertTo-Json -InputObject $AppGroupDetails.Policy -Depth 10 -Compress
        #$AppGroupDetailsJSON_UTF8 = [System.Text.Encoding]::UTF8.GetBytes($AppGroupDetailsJSON)
        
        # Upload Application Group Details
        Write-Log "Upload $($appGroup.PolicyName)" INFO
        $CreateAppGroupDetailsURI = [System.Uri]::new($SourceURI, "Policies/ApplicationGroups/")
        $CreateAppGroupDetails = Invoke-EPMRestMethod -Uri $CreateAppGroupDetailsURI -Method 'POST' -Headers $sessionHeader -Body $AppGroupDetailsJson

        # Store app id for future reference whan processing the policies
        $DestAppGroupMap[$CreateAppGroupDetails.Name] = $CreateAppGroupDetails.Id
    }
}
Write-Box "Application Groups - Done"

# Retrieve and upload Policies
Write-Box "Policies"

<#
# Get Policies
$policiesFilter = ConvertTo-Json @{
    #filter = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
    filter = "PolicyType IN 11,12,13,18,22,23," # Application -> Groups: Advanced, Predefined Policy, Trust
} -Compress
$SearchPolicyURI = [System.Uri]::new($SourceURI, "Policies/Server/Search/")
$policiesList = Invoke-EPMRestMethod -Uri $SearchPolicyURI -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
#>

$SourcePolicies = Get-Policies -RootUri $SourceURI -Headers $sessionHeader

[int[]]$ExcldedPolicyType = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17, 18, 46, 47)

foreach ($policy in $SourcePolicies.Policies) {

    $PolName = $policy.PolicyName
    $PolType = $policy.PolicyType
    
    Write-Log "Processing '$PolName'..." INFO
    
    $PolTypeName = $PolicyTypes[$PolType]

    if ($null -eq $PolTypeName) {
        Write-Log "Policy Type '$PolTypeName' is unknown (Type: '$PolType'). Skipping." WARN
        continue
    }

    if ($ExcldedPolicyType.Contains($PolType)) {
        Write-Log "Policy Type '$PolTypeName' (Type: '$PolTypeName') not supported. Skipping." WARN
        continue
    }

    $SafePolicyId = [uri]::EscapeDataString($policy.PolicyId)
    $PolicyDetailsURI = [System.Uri]::new($SourceURI, "Policies/Server/$SafePolicyId/")
    $PolicyDetails = Invoke-EPMRestMethod -Uri $PolicyDetailsURI -Method 'GET' -Headers $sessionHeader

    # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
    $PolicyDetails.Policy.PSObject.Properties.Remove("Id")
    
    # If policy is linked to App Group, the application group detail defined in the policy must be updated
    # with the new value assigned during the Applicaiton Group creation in the previous phase
    for ($i = 0; $i -lt $PolicyDetails.Policy.Applications.Count; $i++) {
        
        $CurrentApp = $PolicyDetails.Policy.Applications[$i]
        $AppType = $CurrentApp.applicationType
        $AppName = $CurrentApp.displayName
        $AppId = $CurrentApp.id

        if ($AppType -eq 2) {
            
            Write-Log "Processing '$AppName' - '$Appid'" DEBUG
            
            # Check if the application group ID is available in the Application Group mapping
            if ($DestAppGroupMap.ContainsKey($AppName)) {
                # Update the application's id with the found key from the destination map
                $CurrentApp.id = $DestAppGroupMap[$AppName]
                Write-Log "Successfully updated '$AppName' with new ID '$($CurrentApp.id)'." DEBUG
            } else {
                Write-Log "Mapping missing for $AppName. The payload will retain the old ID: '$Appid'." WARN
            }
        }
    }
    
    #Convert as JSON ready to be uploaded
    $PolicyDetailsJson = ConvertTo-Json -InputObject $PolicyDetails.Policy -Depth 10 -Compress
    
    # Upload Application Group Details
    Write-Log "Upload $($policy.PolicyName)" INFO
    $UpPolicyDetailsURI = [System.Uri]::new($DestURI, "Policies/Server/")
    $UpPolicyDetails = Invoke-EPMRestMethod -Uri $UpPolicyDetailsURI -Method 'POST' -Headers $sessionHeader -Body $PolicyDetailsJson
}
 
Write-Box "Policies - Done"

# Retrieve and upload Agent Conf
Write-Box "Default Agent Configuration"
$GeneralAgentConfURI = [System.Uri]::new($SourceURI, "AgentConfiguration/$SafeSourceSetId/")
$GeneralAgentConf = Invoke-EPMRestMethod -Uri $GeneralAgentConfURI -Method 'POST' -Headers $sessionHeader

$GeneralAgentConf.Policy.Id = $SafeDestSetId
$GeneralAgentConfJson = ConvertTo-Json -InputObject $GeneralAgentConf.Policy -Depth 10 -Compress

$UpGeneralAgentConfURI = [System.Uri]::new($DestURI, "Policies/AgentConfiguration/$SafeDestSetId/")    
$UpGeneralAgentConf = Invoke-EPMRestMethod -Uri $UpGeneralAgentConfURI -Method 'PUT' -Headers $sessionHeader -Body $GeneralAgentConfJson

Write-Box "Default Agent Configuration - Done"


