<#
.SYNOPSIS
    Move Computers from one SET to another

.DESCRIPTION
    Move Computers from one SET to another reading the input from csv having the list of computer

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER OATH2
    The ISPSS OATH2 Application Address (e.g., https://<your-tenant>.cyberark.cloud/oidc/token).

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER computerList
    The path to the CSV file containing the list of computers to be moved.

.PARAMETER destSetName
    The name of the destination EPM set.

.NOTES
    File: Move-EpmEndpoint.ps1
    Author: Giulio Compagnone
    Company: Palo Alto Networks
    Version: 0.5
    Created: 02/2025
    Last Modified: 10/2026
    - 26/09/2025: Improve managent fo more than 5000 device
    - 02/10/2025: Add support for OAUTH2 authentication
                  Refactor code use moderm RestAPI
                  Renamed the script to Move-EpmEndpoint.ps1

.EXAMPLE
    .\Move-EpmEndpoint.ps1 -username user@domain -tenant eu -set "Set Name" -computerList "file" -destSetName "dest Set Name" -log
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage="ISPSS OATH2 Application Address")]
    [string]$OATH2,

    [Parameter(Mandatory = $true, HelpMessage="CSV file list of computers")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$computerList,

    [Parameter(Mandatory = $true, HelpMessage="Destination Set")]
    [string]$destSetName,

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

function Move-EPMEndpoint {
<#
.SYNOPSIS
    Move EPM endpoints in batches, respecting API character limits (10.000).

.DESCRIPTION
    Processes the filter string performs a bulk move to the destination SET.
    Documentation: https://docs.cyberark.com/epm/latest/en/content/webservices/endpoint-apis/move-endpoints-set.htm
    Works only for ID and Name filter, other filters are not supported.

.PARAMETER BaseUri
    The base URL of the EPM Manager (e.g., https://na123.epm.cyberark.com/EPM/API/Sets/<SetId>/).
.PARAMETER SessionHeader
    The hashtable containing the Authorization header/token.
.PARAMETER Filter
    An strings containing the filter.
.PARAMETER DestSetId
    The Unique ID of the Destination EPM Set.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uri]$BaseUri,

        [Parameter(Mandatory = $true)]
        [hashtable]$SessionHeader,

        [Parameter(Mandatory = $true)]
        [ValidateSet("id", "name")] # Supported only "id" and "name" filters
        [string]$FilterType,

        [Parameter(Mandatory = $true)]
        [array]$FilterArray,

        [Parameter(Mandatory = $true)]
        [ValidateSet("EQ", "IN", "CONTAINS")]
        [string]$FilterOperator,        

        [Parameter(Mandatory = $true)]
        [string]$DestSetId
    )

    $MoveEndpointsParam = @{
        Uri = [System.Uri]::new($BaseUri, 'Endpoints/moveset')
        Method = 'POST' 
        Headers = $SessionHeader
        Body = $null
    }
    
    # --- API Constraints Documentation & Logic ---
    # Limit: 10,000 characters for the filter string.
    $MaxCharLimit = 10000
    $TotalCount   = $FilterArray.Count

    Write-Log "Starting batch move for $TotalCount endpoints." INFO

    $BasePrefix = "$FilterType $FilterOperator "
    $BaseLength = $BasePrefix.Length

    $CurrentBatch = [System.Collections.Generic.List[string]]::new()
    $CurrentCharCount = $BaseLength

    foreach ($item in $FilterArray) {
        if (($BaseLength + $Item.Length) -gt $MaxCharLimit) {
            Write-Log "Security/Validation: Item '$Item' exceeds the maximum API length alone. Skipping." WARN
            continue
        }

        $AdditionalLength = $Item.Length

        if (($CurrentCharCount + $AdditionalLength) -gt $MaxCharLimit) {
        
            $FilterString = $BasePrefix + [string]::Join(",", $CurrentBatch)
        
            Write-Log "Executing batch of $($CurrentBatch.Count) items. Total Bytes: $($FilterString.Length)" INFO
            
            $MoveEndpointsParam.Body = ConvertTo-Json @{ 
                "filter"    = $FilterString
                "targetSet" = $DestSetId
            } -Compress

            Write-Log "Moving batch of $CurrentBatchSize endpoints" INFO

            $Result = Invoke-EPMRestMethod @MoveEndpointsParam

            if ($Result.statuses.psobject.Properties.Count -gt 0) {
                foreach ($prop in $Result.statuses.psobject.Properties) {
                    $LogLevel = if ($prop.Name -eq "OK") { "INFO" } else { "WARN" }
                    Write-Log "Batch Result - Status: $($prop.Name), Count: $($prop.Value)" $LogLevel
                }
            } else {
                Write-Log "No Endpoints founds to be moved." WARN
            }

            $CurrentBatch.Clear()
            $CurrentCharCount = $BaseLength
        
            $AdditionalLength = $Item.Length 
        }

        $CurrentBatch.Add($Item)
        $CurrentCharCount += $AdditionalLength
    }

    # Flush the remaining items in the buffer (the final partial batch)
    if ($CurrentBatch.Count -gt 0) {
        $FilterString = $BasePrefix + [string]::Join(",", $CurrentBatch)

        Write-Log "Executing final batch of $($CurrentBatch.Count) items. Total Bytes: $($FilterString.Length)" INFO

        $MoveEndpointsParam.Body = ConvertTo-Json @{ 
            "filter"    = $FilterString
            "targetSet" = $DestSetId
        } -Compress

        Write-Log "Moving batch of $CurrentBatchSize endpoints" INFO

        $Result = Invoke-EPMRestMethod @MoveEndpointsParam

        if ($Result.statuses.psobject.Properties.Count -gt 0) {
            foreach ($prop in $Result.statuses.psobject.Properties) {
                $LogLevel = if ($prop.Name -eq "OK") { "INFO" } else { "WARN" }
                Write-Log "Batch Result - Status: $($prop.Name), Count: $($prop.Value)" $LogLevel
            }
        } else {
            Write-Log "No Endpoints founds to be moved." WARN
            }
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


$MoveList = [System.Collections.Generic.List[string]]::new(
            [System.IO.File]::ReadAllLines($computerList)
        )

$Operator = if ($MoveList.Count -eq 1) { "EQ" } else { "IN" }

Move-EPMEndpoint -BaseUri $SourceURI -SessionHeader $sessionHeader -DestSetId $SafeDestSetId -FilterType name -FilterArray $MoveList -FilterOperator $Operator