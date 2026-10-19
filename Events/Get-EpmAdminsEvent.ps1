<#
.SYNOPSIS
    Example script to get Set Admins Events.

.DESCRIPTION
    Tris script is based on the ISPSS events.

.PARAMETER username
    Mandatory: Yes
    The EPM username (e.g., user@domain).

.PARAMETER setId
    Mandatory: No
    The ID of the EPM set.

.PARAMETER tenant
    Mandatory: Yes
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder
    Mandatory: Conditional
    Specifies the folder where data will be stored. This parameter is mandatory in Audit Mode.

.EXAMPLE

.NOTES
    Author: Giulio Compagnone
    Company: Palo Alto Networks
    Version: 0.1
    Created: 10/2026
    Last Modified: 10/2026
#>

param (
    # --- EPM Authentication & Target Parameters ---
    [Parameter(Mandatory = $true, HelpMessage = "Please enter valid EPM username (e.g., user@domain).")]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter(Mandatory = $true, HelpMessage = "Please enter the ISPSS Login URL.")]
    [ValidateNotNullOrEmpty()]
    [uri]$IspssLoginUrl,

    [Parameter(Mandatory = $true, HelpMessage = "Please enter the ISPSS Audit URL.")]
    [ValidateNotNullOrEmpty()]
    [uri]$IspssAuditUrl,    

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder
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

function Connect-EpmIspssAudit {
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
        
        $headers = @{ 
            "Authorization" = "Basic $base64" 
        }
        $body    = @{ 
            "grant_type" = "client_credentials"
            "scope" = "isp.audit.events:read"
        }

        $login = Invoke-RestMethod -Uri $OATH2 -Method Post -Headers $headers -Body $body -ContentType "application/x-www-form-urlencoded"

        # Ensure the response contains the expected fields
        if (-not $login -or -not $login.access_token -or -not $login.token_type -or -not $login.expires_in) {
            $msg = "EPM authentication failed on {0}: Missing expected response fields." -f $OATH2
            Write-Log $msg ERROR
            throw $msg
        }

        # Return a custom object with connection information
        return $login
    }
    catch {
        $msg = "Failed to connect to EPM tenant: {0}. Error: {1}" -f $OATH2, $_.Exception.Message
        Write-Log $msg ERROR
        throw $msg
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
$credential = Get-Credential -UserName $Username -Message "Enter password for $Username"

if ($null -eq $credential) {
    Write-Log "Failed to get credentials..." ERROR
    exit
}

# Authentication
$login = Connect-EpmIspssAudit -credential $credential -epmTenant $tenant -OATH2 $IspssLoginUrl

Write-Host -ForegroundColor Cyan 'Authentication required.'
$secureApiKey = Read-Host -Prompt 'Enter API Key' -AsSecureString
# Validation: Ensure the user did not submit an empty/whitespace string
if ($null -eq $secureApiKey -or $secureApiKey.Length -eq 0) {
    throw [System.ArgumentException]::new('The API key cannot be null or empty.')
}

$bstrPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)

# Store the auth header
$sessionHeader = @{
    "Authorization" = "{0} {1}" -f $login.token_type, $login.access_token
    "x-api-key" = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrPointer)
}

# Query Audit
$BodyQuery = @'
{
  "query": {
    "pageSize": 500,
    "selectedFields": [
      "tenant_id",
      "custom_data",
      "arrival_timestamp",
      "checksum",
      "application_code",
      "audit_code",
      "timestamp",
      "user_id",
      "session_id",
      "source",
      "action_type",
      "audit_type",
      "component",
      "target",
      "command",
      "message",
      "username",
      "action",
      "uuid",
      "icon",
      "service_name",
      "identity_type"
    ],
    "filterModel": {
      "applicationCode": [
        {
          "op": "include",
          "params": [
            "EPM"
          ]
        }
      ]
    }
  }
}
'@

$AuditQueryUri = [System.Uri]::new($IspssAuditUrl, 'api/audits/stream/createQuery')
$QueryResult = Invoke-RestMethod -Method Post -Uri $AuditQueryUri -Headers $sessionHeader -Body $BodyQuery -ContentType "application/json"

$BodyResult = ConvertTo-Json -InputObject @{
    "cursorRef" = $QueryResult.cursorRef
}

$AuditReadUri = [System.Uri]::new($IspssAuditUrl, 'api/audits/stream/results')

$AuditResults = Invoke-RestMethod -Method Post -Uri $AuditReadUri -Headers $sessionHeader -Body $BodyResult -ContentType "application/json"
$AuditResults
