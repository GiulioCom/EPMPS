<#
.SYNOPSIS
    

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).
.PARAMETER setName
    The name of the EPM set.
.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).
.PARAMETER TokenUri
    The fully qualified OAuth 2.0 token endpoint URI 
    (e.g., 'https://ACI1234.id.cyberark.cloud/oauth2/token/epmapi'

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

    [Parameter(HelpMessage="The fully qualified OAuth 2.0 token endpoint URI")]
    [string]$TokenUri,
    
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

        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method,

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
        #$null = $Response.EnsureSuccessStatusCode()

        # 6. Inbound Payload Decoding (Strict UTF-8 Byte Extraction)
        $Bytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $JsonString = [System.Text.Encoding]::UTF8.GetString($Bytes)

        if (-not $Response.IsSuccessStatusCode) {
            throw [System.Management.Automation.RuntimeException]::new($JsonString)
        }

        # 7. Memory Optimization: Return raw string if requested
        if ($Raw.IsPresent) {
            return $JsonString
        }

        return ($JsonString | ConvertFrom-Json)
    }
    catch {
        #Write-Error -Message "EPM HttpClient request failed: $_" -Category ConnectionError
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

function Invoke-EpmRestMethod {
<#
.SYNOPSIS
    Domain orchestration wrapper for EPM REST API calls, managing retry logic and error parsing.
.DESCRIPTION
    Delegates the actual HTTP transport to the high-performance Invoke-EpmHttpClient.
    Handles rate-limiting (EPM00000AE) and specific API state errors cleanly.
#>
    param (
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    $RetryDelay = 120

    $MaxRetries = 3
    $retryCount = 0

    while ($retryCount -lt$MaxRetries) {
        try {
            return Invoke-EpmHttpClient -Uri $URI -Method $Method -Body $Body -Headers $Headers
        }
        catch {
            $ErrorDetailsMessage = $null
            
            # Because of our tweak to Invoke-EpmHttpClient, the exception message IS the raw EPM JSON.
            $rawErrorString = $_.Exception.Message
            
            # Try to parse the thrown string as JSON
            if (-not [string]::IsNullOrWhiteSpace($rawErrorString)) {
                $ErrorDetailsMessage = $rawErrorString | ConvertFrom-Json -ErrorAction SilentlyContinue
            }

            # If it's not JSON, it might be a DNS or connection failure (e.g., host unreachable)
            if ($null -eq $ErrorDetailsMessage) {
                # SECURITY PILLAR: Sanitize string to prevent log forging (newline injection)
                $safeUri = $URI.ToString() -replace "`r|`n", ""
                $safeRawError = $rawErrorString -replace "`r|`n", " "
                
                Write-Log "API call failed for URI: $safeUri. Raw HTTP Error: $safeRawError" "ERROR"
                throw $_.Exception.Message
            }

            # Handle rate limit error (EPM00000AE)
            if ($ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                # RESOURCE PILLAR: Use Regex named capture group instead of creating a secondary array with -replace
                $pattern = "(?<minutes>\d+)\s+minute"
                $match = [regex]::Match($ErrorDetailsMessage.ErrorMessage, $pattern)
                
                if ($match.Success) {
                    $minutes = [int]$match.Groups['minutes'].Value
                    $RetryDelay = $minutes * 60
                    Write-Log "Rate limit hit. Retrying in $RetryDelay seconds..." "WARN"
                } else {
                    Write-Log "Rate limit hit. Retrying in $RetryDelay seconds (default)..." "WARN"
                }
                
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } 
            else {
                # Handle filter errors or target mismatch errors
                $safeErrorCode = $ErrorDetailsMessage.ErrorCode -replace "`r|`n", ""
                $safeErrorMsg  = $ErrorDetailsMessage.ErrorMessage -replace "`r|`n", " "

                if ($safeErrorCode -eq "EPM000002E" -and $null -ne$Body) {
                    Write-Log "ErrorCode: $safeErrorCode, ErrorMessage: $safeErrorMsg" ERROR
                    Write-Log "Please verify the filter body if present, as it could be the cause of this error." ERROR
                    throw "ErrorCode: $safeErrorCode, ErrorMessage:$safeErrorMsg"
                } 
                elseif ($safeErrorCode -eq "EPM000012E") {
                    Write-Log "ErrorCode: $safeErrorCode, ErrorMessage:$safeErrorMsg" "ERROR"
                    return
                }
                else {
                    # Log and throw any other unhandled API error
                    Write-Log "ErrorCode: $safeErrorCode, ErrorMessage: $safeErrorMsg" "ERROR"
                    throw "ErrorCode: $safeErrorCode, ErrorMessage: $safeErrorMsg"
                }
            }
        }
    }

    Write-Log "API call failed after $MaxRetries retries. URI: $($URI -replace '[\r\n]', '')" ERROR
    throw "API call failed after $MaxRetries retries."
}

function Invoke-EPMRestMethod-Old {
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
        [hashtable]$Headers
    )

    $RetryDelay = 60 # Default value, in case of the returned message doesn't contain the limit info

    $MaxRetries = 3
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
function Connect-Epm {
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

function Connect-EpmIspss {
<#
.SYNOPSIS
    Connects to CyberArk EPM using the ISPSS OIDC/OAuth portal.
.DESCRIPTION
    Authenticates against CyberArk Identity ISPSS via client_credentials, retrieves an access token,
    and queries the tenant's base manager URL. Keeps credentials secure in memory using byte arrays.
.PARAMETER Credential
    The PSCredential object representing the client ID (Username) and client secret (Password).
.PARAMETER EpmTenant
    The EPM tenant name (e.g., eu, uk).
.PARAMETER TokenUri
    The fully qualified OAuth 2.0 token endpoint URI 
    (e.g., 'https://ACI4617.id.cyberark.cloud/oauth2/token/epmapiapp').
.OUTPUTS
    [PSCustomObject] Authetication Result.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        #[Parameter(Mandatory = $true)]
        #[string]$EpmTenant,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$TokenUri
    )

    # Login ISPSS
    try {
        $rawCreds = "{0}:{1}" -f $credential.UserName, $credential.GetNetworkCredential().Password
        $base64   = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawCreds))
        
        # Clean up the clear text variable
        $rawCreds = $null
        
        $headers = @{ 
            "Authorization" = "Basic $base64"
        }
        $body = @{
             grant_type = "client_credentials" 
        }

        $login = Invoke-RestMethod -Uri $TokenUri -Method Post -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"

        # Ensure the response contains the expected fields
        if (-not $login -or -not $login.access_token -or -not $login.token_type -or -not $login.expires_in) {
            $msg = "EPM authentication failed on {0}: Missing expected response fields." -f $TokenUri
            Write-Log $msg ERROR
            throw $msg
        }

        return $login
        #$access_token = $login.access_token

    }
    catch {
        $msg = "Failed to connect to EPM tenant: {0}. Error: {1}" -f $url, $_.Exception.Message
        Write-Log $msg ERROR
        throw $msg
    }

<#
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
#>
}

function Get-EpmSetID {
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
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ $_.Scheme -eq 'https' })]
        [System.Uri]$EpmBaseUri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$setName
    )

    # Retrieve list of sets
    try {
        $setsResponse = Invoke-EPMRestMethod -URI $EpmBaseUri -Method 'GET' -Headers $Headers
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

Function Get-Endpoints {
<#
.SYNOPSIS
    Retrieves a list of EPM Computers from a CyberArk EPM server, handling pagination automatically.

.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get computers.
    It automatically manages pagination by making multiple API calls if the total number
    of computers exceeds the API limit. The results are merged efficiently into a single object.
.PARAMETER RootURI
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
        [string]$RootURI,

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
        $URI = '{0}/Endpoints/search?offset={1}&limit={2}' -f $RootURI.TrimEnd('/'), $offset, $limit
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

Function Get-PoliciesAppGroup {
<#
.SYNOPSIS
    Retrieves a list of EPM policies from a CyberArk EPM server, handling pagination automatically.
.DESCRIPTION
    This function acts as a wrapper for the CyberArk EPM REST API to get policies.
    It automatically manages pagination by making multiple API calls if the total number
    of policies exceeds the API's maximum limit (1000). The function merges all
    policies into a single PSCustomObject for easy management.
.PARAMETER EpmSetUri
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
        [System.Uri]$EpmSetUri,

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

    $BaseEndpoint = [System.Uri]::new($EpmSetUri, $TargetTypeURL)
    $UriBuilder = [System.UriBuilder]::new($BaseEndpoint)

    do {
        # Prepare Query
        $QueryElements = [System.Collections.Generic.List[string]]::new()
        $QueryElements.Add("offset=$offset")
        $QueryElements.Add("limit=$limit")
        
        if (-not [string]::IsNullOrWhiteSpace($sortBy)) { $QueryElements.Add("sortBy=$sortBy") }
        if (-not [string]::IsNullOrWhiteSpace($sortDir)) { $QueryElements.Add("sortDir=$sortDir") }

        $UriBuilder.Query = [string]::Join('&', $QueryElements)
        $RequestParam.URI = $UriBuilder.Uri
        
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

function Add-EndpointToPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootURI,

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
        
    $URI = '{0}/Policies/Server/{1}' -f $RootURI.TrimEnd('/'), $PolicyId
    
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

[uri]$EpmBaseUri = $null

# Authentication
if (-not $TokenUri){
    Write-Log "Legacy authetication..." INFO
    $login = Connect-EPM -credential $credential -epmTenant $tenant
    $Auth = 'basic {0}' -f $login.auth
    $EpmBaseUri = "$($login.managerURL)/EPM/API/Sets/"

} else {
    Write-Log "Modern authetication to $($TokenUri)..." INFO
    $login = Connect-EpmIspss -credential $credential -TokenUri $TokenUri
    $Auth = '{0} {1}' -f $login.token_type, $login.access_token
    $EpmBaseUri = "https://api-$($tenant).epm.cyberark.cloud/api/sets/"
}

# Store the auth header
$SessionHeader = @{
    "Authorization" = "$Auth"
}

$EpmSetData = Get-EpmSetID -EpmBaseUri $EPMBaseUri -Headers $SessionHeader -setName $SetName

$EpmSetUri = [System.Uri]::new($EPMBaseUri, "$($EpmSetData.setId)/")

Write-Log "Entering SET: $($EpmSetData.setName)..." INFO -ForegroundColor Blue

#Example Request 

# Test GetPolicies
$i = 1
while ($true) {
    $policies = Get-PoliciesAppGroup -EpmSetUri $EpmSetUri -Headers $SessionHeader -TargetType Policy
    $policies
    Write-Log "Attempt $i" INFO
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