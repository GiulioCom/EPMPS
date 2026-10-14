<#
.SYNOPSIS
    Automates the bulk import of Application Definitions into CyberArk EPM Application Groups.

.DESCRIPTION
    This script reads application data (Publishers and Group Names) from a CSV file and 
    add them to existing or newly created Application Groups in CyberArk EPM. 
    
.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant region/instance to connect to. Used to construct the correct API URL.
    Input is validated against a known set of regions to prevent injection attacks.
    (Accepted values: login, eu, uk, au, ca, in, jp, sg, it, ch)

.PARAMETER CsvPath
    The Application Definition csv file having the following header:
    AppGroupName,PropertyType,Value,CompareAs

    PropertyType can be FileName or Publisher

    CompareAs is a string value based the official docs: https://docs.cyberark.com/epm/latest/en/content/webservices/applicationpatterns.htm#Publisher
    - exact
    - prefix
    - contains
    - wildcards
    - regExp

.PARAMETER log
    Enable logging to file and console

.PARAMETER logFolder
    Specify the log file path

.EXAMPLE
    .\Add-ApplicationDefinition.ps1' -username user@upn -tenant eu -CsvPath "c:\app_def_pub.csv"    

.NOTES
    Author: Giulio Compagnone
    Company: Palo Alto Networks
    Version: 0.5
    Created: 06/2025
    Update: 10/2026
#>

[CmdletBinding(DefaultParameterSetName = 'Xml')]
param (
    # --- EPM Authentication & Target Parameters ---
    [Parameter(Mandatory = $true, HelpMessage = "Please enter valid EPM username (e.g., user@domain).")]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory = $false, HelpMessage = "Please enter valid EPM set name.")]
    [ValidateNotNullOrEmpty()]
    [string]$SetName,

    [Parameter(Mandatory = $true, HelpMessage = "Please enter valid EPM tenant region.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch", IgnoreCase = $true)]
    [string]$Tenant,

    # --- Data Source: CSV Parameter Set ---
    [Parameter(
        Mandatory = $true, 
        ParameterSetName = 'Csv', 
        HelpMessage = "Path to the Application Definition CSV file."
    )]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) {
            throw "Target CSV file does not exist or is a folder: '$_'"
        }
        if ([System.IO.Path]::GetExtension($_).ToLowerInvariant() -ne '.csv') {
            throw "Invalid file extension. Expected '.csv' for ParameterSet 'Csv'."
        }
        $true
    })]
    [string]$CsvPath,

    # --- Data Source: XML Parameter Set (EPM File Properties) ---
    [Parameter(
        Mandatory = $true, 
        ParameterSetName = 'Xml', 
        HelpMessage = "Path to the EPM File Properties XML export file."
    )]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Leaf)) {
            throw "Target XML file does not exist or is a folder: '$_'"
        }
        if ([System.IO.Path]::GetExtension($_).ToLowerInvariant() -ne '.xml') {
            throw "Invalid file extension. Expected '.xml' for ParameterSet 'Xml'."
        }
        $true
    })]
    [string]$XmlPath,

    # --- Target Container Parameters (Conditionally Mandatory) ---
    [Parameter(
        Mandatory = $true, 
        ParameterSetName = 'Xml', 
        HelpMessage = "Specify the target container type in EPM ('Policy' or 'ApplicationGroup')."
    )]
    [Parameter(
        Mandatory = $false, 
        ParameterSetName = 'Csv', 
        HelpMessage = "Specify the target container type in EPM ('Policy' or 'ApplicationGroup')."
    )]
    [ValidateSet('Policy', 'ApplicationGroup', IgnoreCase = $true)]
    [string]$TargetType,

    [Parameter(
        Mandatory = $true, 
        ParameterSetName = 'Xml', 
        HelpMessage = "Enter the exact name of the target Policy or Application Group."
    )]
    [Parameter(
        Mandatory = $false, 
        ParameterSetName = 'Csv', 
        HelpMessage = "Enter the exact name of the target Policy or Application Group."
    )]
    [ValidateNotNullOrEmpty()]
    [string]$TargetName,

    # --- Logging & Diagnostics Parameters ---
    [Parameter(Mandatory = $false, HelpMessage = "Enable file and console execution logging.")]
    [switch]$EnableLogging,

    [Parameter(Mandatory = $false, HelpMessage = "Specify the target directory for log output.")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Container)) {
            throw "Target log directory does not exist: '$_'"
        }
        $true
    })]
    [string]$LogFolderPath
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

function Invoke-EpmHttpClient {
<#
.SYNOPSIS
    High-performance REST client using native .NET HttpClient with payload support.
.DESCRIPTION
    Leverages .NET HttpClient to perform synchronous HTTP queries. It natively supports
    JSON payloads, guarantees UTF-8 encoding on both outbound and inbound streams, 
    and offers a -Raw switch to bypass memory-heavy JSON deserialization.
.PARAMETER Uri
    The validated HTTPS URI of the EPM endpoint.
.PARAMETER Method
    The HTTP verb to execute (e.g., GET, POST, PUT, DELETE).
.PARAMETER Headers
    Hashtable containing authorization headers.
.PARAMETER Body
    The JSON string payload to upload (for POST/PUT requests).
.PARAMETER Raw
    Switch to return the raw JSON string instead of a deserialized PowerShell object.
.OUTPUTS
    [object] Deserialized PSCustomObject, or [string] if -Raw is used.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method = 'GET',

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [switch]$Raw
    )

    # 1. Security Pillar: Enforce TLS 1.2+ and HTTPS
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    
    if ($Uri.Scheme -ne [System.Uri]::UriSchemeHttps) {
        throw [System.Security.SecurityException]::new("Insecure transmission blocked. HTTPS is required.")
    }

    # 2. Resource Pillar: Instantiate Http client structures
    $Handler = [System.Net.Http.HttpClientHandler]::new()
    $Client  = [System.Net.Http.HttpClient]::new($Handler)

    # Translate string method to .NET HttpMethod object
    $NetMethod = [System.Net.Http.HttpMethod]::new($Method)
    $Request   = [System.Net.Http.HttpRequestMessage]::new($NetMethod, $Uri)

    try {
        # 3. Secure Header Attachment (Prevents CRLF Injection)
        foreach ($Key in $Headers.Keys) {
            # Skip Content-Type if present; HttpClient sets it at the Content level
            if ($Key -eq 'Content-Type') { continue }
            $null = $Request.Headers.TryAddWithoutValidation($Key, [string]$Headers[$Key])
        }

        # 4. Outbound Payload Construction (UTF-8 Enforced)
        if (-not [string]::IsNullOrEmpty($Body)) {
            # StringContent automatically encodes to UTF-8 and sets the Content-Type header
            $Request.Content = [System.Net.Http.StringContent]::new(
                $Body, 
                [System.Text.Encoding]::UTF8, 
                "application/json"
            )
        }

        # 5. Execute HTTP Call synchronously (Zero PowerShell ETS pipeline overhead)
        $Response = $Client.SendAsync($Request).GetAwaiter().GetResult()
        $null = $Response.EnsureSuccessStatusCode()

        # 6. Inbound Payload Decoding (Strict UTF-8 Byte Extraction)
        $Bytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $JsonString = [System.Text.Encoding]::UTF8.GetString($Bytes)

        # 7. Memory Optimization: Return raw string if requested
        if ($Raw.IsPresent) {
            return $JsonString
        }

        return ($JsonString | ConvertFrom-Json)
    }
    catch {
        Write-Error -Message "EPM HttpClient request failed: $_" -Category ConnectionError
        throw
    }
    finally {
        # 8. Resource Pillar: Deterministic disposal of unmanaged OS resources
        if ($null -ne $Request.Content) { $Request.Content.Dispose() }
        $Request.Dispose()
        $Client.Dispose()
        $Handler.Dispose()
    }
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
Function Get-PoliciesAppGroup {
<#
.SYNOPSIS
    Retrieves a list of EPM policies from a CyberArk EPM server, handling pagination automatically.
.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get policies.
    It automatically manages pagination by making multiple API calls if the total number
    of policies exceeds the API's maximum limit (1000). The function merges all
    policies into a single PSCustomObject for easy management.
.PARAMETER RootUri
    The base URI of the EPM API.
.PARAMETER Headers
    The authorization headers for the API request.
.PARAMETER TargetType
    The type of policy to search into, it can be Policy or ApplicationGroup
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

        [ValidateSet('Policy', 'ApplicationGroup', IgnoreCase = $true)]
        [string]$TargetType,
        
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

    switch ($TargetType) {
        'Policy' {
            $TargetTypeURL = 'Policies/Server/Search'
        }
        'ApplicationGroup' {
            $TargetTypeURL = 'Policies/ApplicationGroups/Search'
        }
    }

    $baseEndpoint = [System.Uri]::new($RootUri, $TargetTypeURL)
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

### Script function
function Test-EpmGroupCapacity {
    <#
    .SYNOPSIS
        Validates if adding new applications will exceed the EPM limit.
    .PARAMETER CurrentCount
        The number of applications currently in the EPM group.
    .PARAMETER NewItemsCount
        The number of applications being added.
    .PARAMETER GroupName
        The name of the group for logging purposes.
    .EXAMPLE
        if (Test-EpmGroupCapacity -CurrentCount 500 -NewItemsCount 10 -GroupName "MyGroup") { ... }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$CurrentCount,

        [Parameter(Mandatory = $true)]
        [int]$NewItemsCount,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    $EpmLimit = 1000
    $TotalPotentialCount = $CurrentCount + $NewItemsCount

    if ($TotalPotentialCount -gt $EpmLimit) {
        $RemainingSpace = [Math]::Max(0, ($EpmLimit - $CurrentCount))
        
        Write-Log "CRITICAL: Group '$GroupName' limit exceeded! Current: $CurrentCount, New: $NewItemsCount. Limit is $EpmLimit." ERROR
        Write-Log "Action: You can only add $RemainingSpace more items to this group." WARN
        
        return $false
    }

    Write-Log "Capacity Check Passed for '$GroupName': $TotalPotentialCount/$EpmLimit slots used." INFO
    return $true
}

function Get-EpmFilteredFileInfo {
<#
.SYNOPSIS
    Parses CyberArk EPM XML file exports without relying on the pipeline.
.DESCRIPTION
    Reads an EPM File Properties XML document linearly using [System.Xml.XmlReader].
    Filters property tags against a high-performance O(1) HashSet allowlist, 
    discards unneeded elements at the stream level, and accumulates extracted 
    data into a strongly typed generic List.
.PARAMETER Path
    The validated file path to the target EPM XML file.
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] Collection of extracted application properties.
.EXAMPLE
    $EpmData = Get-EpmFilteredFileInfo -Path "C:\EpmExports\FileProperties.xml"
#>
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $ResolvedPath = Convert-Path -Path $Path -ErrorAction Stop

    $XmlSettings = [System.Xml.XmlReaderSettings]::new()
    $XmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $XmlSettings.XmlResolver = $null

    $AllowedProperties = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $AllowedProperties.UnionWith([string[]]@(
        'Path',
        'Publisher',
        'Publisher Status',
        'OriginalFilename',
        'File Version (fixed)',
        'File Version (string)',
        'File Description',
        'Product Name',
        'Product Version (fixed)',
        'Product Version (string)',
        'requestedExecutionLevel',
        'SHA1',
        'SHA256'
    ))

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Reader = $null
    try {
        # Initialize streaming XML Reader
        $Reader = [System.Xml.XmlReader]::Create($ResolvedPath, $XmlSettings)

        while ($Reader.Read()) {
            if ($Reader.NodeType -eq [System.Xml.XmlNodeType]::Element -and $Reader.Name -eq 'FileInfo') {
                
                # Order properties to maintain deterministic output structure
                $FilteredProps = @{}

                # Isolate stream scope to current FileInfo node
                $Subtree = $Reader.ReadSubtree()

                while ($Subtree.Read()) {
                    if ($Subtree.NodeType -eq [System.Xml.XmlNodeType]::Element -and $Subtree.Name -eq 'Prop') {
                        $PropName = $Subtree.GetAttribute('name')

                        if (-not [string]::IsNullOrEmpty($PropName) -and $AllowedProperties.Contains($PropName)) {
                            $FilteredProps[$PropName] = $Subtree.ReadElementContentAsString()
                        }
                    }
                }
                $Subtree.Dispose()

                if ($FilteredProps.Count -gt 0) {
                    $Results.Add([PSCustomObject]$FilteredProps)
                }
            }
        }
    }
    catch {
        Write-Log "Failed to parse XML file at '$ResolvedPath': $_" ERROR
    }
    finally {
        if ($null -ne $Reader) {
            $Reader.Dispose()
        }
    }

    return $Results
}

function Get-EpmFileNamePattern {
<#
.SYNOPSIS
    Generates both FILE_NAME and LOCATION EPM pattern structures from a single file path.
.DESCRIPTION
    Decomposes a file path string into its leaf filename and parent directory using .NET
    System.IO.Path static methods. Returns an ordered hashtable containing both 'FILE_NAME' 
    and 'LOCATION' pattern dictionaries for CyberArk EPM REST API payloads.
.PARAMETER Path
    The raw file path string extracted from the EPM XML source.
.PARAMETER Sha1
    The optional SHA1 hash string associated with the file.
.OUTPUTS
    [ordered] Hashtable containing 'FILE_NAME' and/or 'LOCATION' pattern entries.
.EXAMPLE
    $PathPatterns = Get-EpmFileNamePattern -Path "C:\Windows\System32\powershell.exe" -Sha1 "A4F874F6..."
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Sha1 = ""
    )

    $PathPatterns = @{}

    # 1. Extract Leaf Filename for FILE_NAME Pattern
    $FileName = [System.IO.Path]::GetFileName($Path)
    if (-not [string]::IsNullOrWhiteSpace($FileName)) {
        $PathPatterns["FILE_NAME"] = @{
            "@type"         = "FileName"
            "hashAlgorithm" = "SHA1"
            "hash"          = $Sha1
            "fileSize"      = 0
            "isEmpty"       = $false
            "content"       = $FileName
            "compareAs"     = 0
        }
    }

    # 2. Extract Parent Directory for LOCATION Pattern
    $DirectoryPath = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($DirectoryPath)) {
        $PathPatterns["LOCATION"] = @{
            "@type"          = "Location"
            "content"        = $DirectoryPath
            "withSubfolders" = $false
            "caseSensitive"  = $false
            "isEmpty"        = $false
        }
    }

    return $PathPatterns
}

function Update-PolicyAppGroup {
<#
.SYNOPSIS
    Updates an EPM policy's application group with new applications.
.DESCRIPTION
    This function sends a PATCH request to the EPM API to update the specified policy's
    application group with the provided applications. It handles logging and error checking.
.PARAMETER RootUri
    The base URI of the EPM API.
.PARAMETER Headers
    The authorization headers for the API request.
.PARAMETER TargetType
    The type of policy to search into, it can be Policy or ApplicationGroup
.PARAMETER TargetName
    The name of the policy or the application group to update.
.PARAMETER Applications
    Application objects to add to the policy or the application group.
#>
    param (
        [Parameter(Mandatory = $true)]
        [System.Uri]$RootUri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$TargetName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Policy', 'ApplicationGroup', IgnoreCase = $true)]
        [string]$TargetType,
        
        [Parameter(Mandatory = $true)]
        [object]$ApplicationDefinition
    )

    $TargetList = Get-PoliciesAppGroup -RootUri $RootUri -Headers $Headers -TargetType $TargetType -filter "PolicyName eq `"$TargetName`""

    if ($TargetList.Policies.Count -eq 0) {
        Write-Log "No $TargetType found with the name '$TargetName'. Exiting." ERROR
        return
    } elseif ($TargetList.Policies.Count -gt 1) {
        Write-Log "Multiple $TargetType objects found with the name '$TargetName'. Please ensure unique names. Exiting." ERROR
        return
    }

    $PolicyId = $TargetList.Policies[0].PolicyId
    Write-Log "Found $TargetType '$TargetName' with ID: $PolicyId" INFO

    switch ($TargetType) {
        'Policy' {
            $TargetTypeURL = "Policies/Server/$PolicyId"
        }
        'ApplicationGroup' {
            $TargetTypeURL = "Policies/ApplicationGroups/$PolicyId"
        }
    }  
    
    $baseEndpoint = [System.Uri]::new($RootUri, $TargetTypeURL)

    $PolicyDetails = Invoke-EpmHttpClient -Uri $baseEndpoint -Method 'GET' -Headers $Headers
    $PolicyDefinition = $PolicyDetails.Policy
    
    $CombinedApps = [System.Collections.Generic.List[object]]::new($PolicyDefinition.Applications.Count + 1)
    $CombinedApps.AddRange([object[]]$PolicyDefinition.Applications)
    $CombinedApps.Add($ApplicationDefinition)

    $PolicyDefinition.Applications = $CombinedApps

    $UpdateJson = ConvertTo-Json -InputObject $PolicyDefinition -Depth 10 -Compress
    $UpdateResponse = Invoke-EpmHttpClient -Uri $baseEndpoint -Method 'PUT' -Headers $Headers -Body $UpdateJson

    if ($null -ne $UpdateResponse) {
        Write-Log "Successfully updated $TargetType '$TargetName' with new application definition." INFO
    } else {
        Write-Log "Failed to update $TargetType '$TargetName'." ERROR
    }
}

### Begin Script ###

### Mappting
$CompareAsMap = @{
    "exact"     = 0
    "prefix"    = 1
    "contains"  = 2
    "wildcards" = 3
    "regExp"    = 4
}

## Prepare log folder and file
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)

$script:EnableLogging = $EnableLogging.IsPresent
$script:LogFilePath   = $null

if ($script:EnableLogging) {
    if (-not $PSBoundParameters.ContainsKey('LogFolderPath')) {
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
}

# Define the root endpoint
[System.Uri]$EPMBaseUri = $login.managerURL.TrimEnd('/') + '/'
$SetData = Get-EPMSetID -managerURL $EPMBaseUri -Headers $sessionHeader -setName $SetName
$EPMUri = [System.Uri]::new(
    $EPMBaseUri, 
    "EPM/API/Sets/$([System.Uri]::EscapeDataString($SetData.setId))/"
)


switch ($PSCmdlet.ParameterSetName) {
    'Xml' {
        Write-Log "Processing XML source: $XmlPath" INFO
        $ExtractedFileProperties = Get-EpmFilteredFileInfo $XmlPath

        if ($ExtractedFileProperties.Count -eq 0) {
            Write-Log "No valid file properties extracted from XML. Exiting." ERROR
            return
        }

        $Patterns = Get-EpmFileNamePattern -Path $ExtractedFileProperties.Path -Sha1 $ExtractedFileProperties.SHA1
        
        if ($ExtractedFileProperties.'Publisher Status' -eq 'Signature verified' -and 
            -not [string]::IsNullOrWhiteSpace($ExtractedFileProperties.'Publisher')) {
            $Patterns["PUBLISHER"] = @{
                "@type"          = "Publisher"
                "caseSensitive"  = $false
                "compareAs"      = 1
                "content"        = [string]$ExtractedFileProperties.'Publisher'
                "isEmpty"        = $false
                "separator"      = ";"
                "signatureLevel" = 2
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ExtractedFileProperties.'OriginalFilename')) {
            $Patterns["ORIGINAL_FILE_NAME"] = @{
                "@type"          = "FileInfo"
                "elementName"    = "FileVerInfo"
                "attributeInfoName" = "OriginalFilename"
                "isEmpty"        = $false
                "content"        = [string]$ExtractedFileProperties.'OriginalFilename'
                "compareAs"      = 0
                "caseSensitive"  = $false
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ExtractedFileProperties.'File Description')) {
            $Patterns["FILE_DESCRIPTION"] = @{
                "@type"          = "FileInfo"
                "elementName"    = "FileVerInfo"
                "attributeInfoName" = "FileDescription"
                "isEmpty"        = $false
                "content"        = [string]$ExtractedFileProperties.'File Description'
                "compareAs"      = 0
                "caseSensitive"  = $false
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ExtractedFileProperties.'Product Name')) {
            $Patterns["PRODUCT_NAME"] = @{
                "@type"          = "FileInfo"
                "elementName"    = "FileVerInfo"
                "attributeInfoName" = "ProductName"
                "isEmpty"        = $false
                "content"        = [string]$ExtractedFileProperties.'Product Name'
                "compareAs"      = 0
                "caseSensitive"  = $false
            }
        }

        $NewApplicationsDefinition = @{
            "applicationType" = 3
            "childProcess" = $false
            "description" = "$($ExtractedFileProperties.Path)"
            "displayName" = "$($ExtractedFileProperties.Path)"
            "patterns" = $Patterns
        }


        Write-Log "Updating EPM $TargetType '$TargetName' from XML source '$XmlPath'..." INFO
        Update-PolicyAppGroup -RootUri $EPMUri -Headers $sessionHeader -TargetName $TargetName -TargetType $TargetType -ApplicationDefinition $NewApplicationsDefinition

        
<#        
        if ($Policy) {
            $PolicyList = Get-Policies -RootUri $EPMBaseUri -Headers $sessionHeader -filter "PolicyName eq '$Policy'"
            
            if ($PolicyList.Policies.Count -eq 0) {
                Write-Log "No policy found with the name '$Policy'. Exiting." ERROR
                return
            } elseif ($PolicyList.Policies.Count -gt 1) {
                Write-Log "Multiple policies found with the name '$Policy'. Please ensure unique policy names. Exiting." ERROR
                return
            }

            $PolicyId = $PolicyList.Policies[0].PolicyId
            Write-Log "Found Policy '$Policy' with ID: $PolicyId" INFO

            $PolicyFull = Invoke-EPMRestMethod -Uri "$EPMBaseUri/Policies/Server/$PolicyId" -Method 'GET' -Headers $sessionHeader

            $Policy = $PolicyFull.Policy
            
            $CombinedApps = [System.Collections.Generic.List[object]]::new()
            $CombinedApps.AddRange([object[]]$Policy.Applications)
            $CombinedApps.AddRange($NewApplicationsPayloads)

            $Policy.Applications = $CombinedApps

            $UpdateJson = ConvertTo-Json -InputObject $Policy -Depth 10 -Compress
            
            $UpdateResponse = Invoke-EPMRestMethod -Uri "$EPMBaseUri/Policies/Server/$PolicyId" -Method 'PUT' -Headers $sessionHeader -Body $UpdateJson

            if ($null -ne $UpdateResponse) {
                Write-Log "Successfully updated Policy '$Policy' with new application definition." INFO
            } else {
                Write-Log "Failed to update Policy '$Policy'." ERROR
            }

        } else {
            Write-Log "Application Group process here." WARN
        }
#>
    }
    'Csv' {

        # Get the list of AppGroups and build a map for fast search
        Write-Log "Retrieving the Application Groups Data..." INFO

        $AppGroups = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader
        $AppGroupsMap = @{}
        foreach ($AppGroup in $AppGroups.Policies) {
            $AppGroupsMap[$AppGroup.PolicyName.Trim()] = $AppGroup.PolicyId
        }

        Write-Log "Importing data from $CsvPath..." INFO

        # Validate CSV
        $FirstRow = Import-Csv -Path $CsvPath -Encoding utf8 | Select-Object -First 1
        if (-not $FirstRow) {
            $ErrorMessage = "Schema Error: $CsvPath is empty or missing valid headers."
            Write-Log $ErrorMessage ERROR
            throw $ErrorMessage
        }

        $RawHeader = $FirstRow.psobject.properties.name
        $RequiredHeaders = @('AppGroupName', 'PropertyType','Value','CompareAs')

        foreach ($Header in $RequiredHeaders) {
            if ($Header -notin $RawHeader) {
                $ErrorMessage = "Schema Error: Missing required column '$Header' in $CsvPath"
                Write-Log $ErrorMessage ERROR
                throw $ErrorMessage
            }
        }

        # Initialize a Hashtable to store AppGroupName as the Key
        # and an ArrayList of Publishers as the Value.
        $AppLookup = @{}

        Import-Csv -Path $CsvPath | ForEach-Object {
            $GroupName = $_.AppGroupName.Trim()
            $PropertyType = $_.PropertyType.Trim()
            $Value = $_.Value.Trim()
            $CompareAs = $_.CompareAs.Trim()

            if (-not $AppLookup.ContainsKey($GroupName)) {
                $AppLookup[$GroupName] = [System.Collections.Generic.List[object]]::new()
            }

            $ValidProperties = @('FileName', 'Publisher')
            
            if ($PropertyType -notin $ValidProperties) {
                Write-Log "Skipping unsupported PropertyType '$PropertyType'. Supported values are $($ValidProperties -join (','))." WARN
                return
            }

            $CompareAsNum = if ($CompareAsMap.ContainsKey($CompareAs)) {
                $CompareAsMap[$CompareAs]
            } else {
                Write-Log "Invalid CompareAs value '$CompareAs' for '$Value' (property '$PropertyType'). Defaulting to 0 (exactly)." WARN
                0 
            }

            $AppData = [PSCustomObject]@{
                Property = $PropertyType
                Value = $Value
                CompareAs = $CompareAsNum
            }

            $AppLookup[$GroupName].Add($AppData)
        }

        foreach ($Entry in $AppLookup.GetEnumerator()) {
            
            $TargetAppGroupName = $Entry.Key
            $AppData = $Entry.Value

            $PropertyMap = @{
                "FileName"  = "FILE_NAME"
                "Publisher" = "PUBLISHER"
            }

            $AppDefinitions = $AppData | ForEach-Object {
                $item = $_

                $propertyKey = $PropertyMap[$item.Property]

                $pattern = @{
                    "@type"     = $item.Property
                    "compareAs" = [int]$item.CompareAs
                    "content"   = $item.Value
                }

                if ($item.Property -eq "Publisher") {
                    $pattern["signatureLevel"] = 2
                }
                
                [PSCustomObject]@{
                    "internalId"      = 0
                    "applicationType" = 3
                    "patterns"        = @{ $propertyKey = $pattern}
                    "childProcess"    = $true
                }
            } 
            
            # Search the App Group in the Map
            if ($AppGroupsMap.ContainsKey($TargetAppGroupName)) {
                $targetAppGroupId = $AppGroupsMap[$TargetAppGroupName]
                Write-Log "Match Found: App Group '$TargetAppGroupName' has ID: $targetAppGroupId" -severity INFO
                
                $appGroup = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/$targetAppGroupId" -Method 'GET' -Headers $sessionHeader

                if (-not (Test-EpmGroupCapacity -CurrentCount $appGroup.Policy.Applications.Count -NewItemsCount $AppDefinitions.Count -GroupName $TargetAppGroupName)) {
                    continue # Skip this group
                }
                
                $finalAppList = [System.Collections.Generic.List[object]]::new($appGroup.Policy.Applications)
            
                foreach ($Def in $AppDefinitions) { $finalAppList.Add($Def) }

                # Update the object reference
                $appGroup.Policy.Applications = $finalAppList
                $AppGroupJSON = [System.Text.Encoding]::UTF8.GetBytes(($appGroup.Policy | ConvertTo-Json -Depth 10 -Compress)) #Force UTF8

                # Update the AppGroup
                $UpdateResponse = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/$targetAppGroupId" -Method 'PUT' -Headers $sessionHeader -Body $AppGroupJSON
                if ($null -ne $UpdateResponse -and $null -ne $UpdateResponse.Id) {
                    Write-Log "SUCCESS: Group '$($UpdateResponse.Name)' updated. Now contains $($UpdateResponse.Applications.Count) application(s)." INFO
                }
            } else {
                Write-Log "Group '$TargetAppGroupName' not found in EPM. Creating the Application Group..." -severity WARN

                if (-not (Test-EpmGroupCapacity -CurrentCount 0 -NewItemsCount $AppDefinitions.Count -GroupName $TargetAppGroupName)) {
                    continue # Skip this group
                }

                $NewAppGroup = @{
                    "Name" = $TargetAppGroupName
                    "PolicyType" = 14
                    "Applications" = $AppDefinitions
                }

                $AppGroupJSON = [System.Text.Encoding]::UTF8.GetBytes(($NewAppGroup | ConvertTo-Json -Depth 10 -Compress)) #Force UTF8

                # Create the AppGroup
                $AddResponse = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups" -Method 'POST' -Headers $sessionHeader -Body $AppGroupJSON
                if ($null -ne $AddResponse -and $null -ne $AddResponse.Id) {
                    Write-Log "SUCCESS: New Application Group '$($AddResponse.Name)' created with ID: $($AddResponse.Id)." -severity INFO
                }
            }
        }
    }
}





