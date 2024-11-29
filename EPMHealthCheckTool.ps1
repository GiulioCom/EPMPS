<#
.SYNOPSIS
    Health Check: Get Default Policy and Agent Configuration

.DESCRIPTION
    
.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.NOTES
    File: EPMHCGetInfo.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1 - INTERNAL
    Date: 10/2024
    
.EXAMPLE
    .\EPMHCGetInfo.ps1 -username "user@domain" -setName "MySet" -tenant "eu"
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
    [string]$logFolder
)

### General Functions
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
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$severity] - $message"

    switch ($severity) {
        "INFO" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Green"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
        "WARN" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Yellow"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
        "ERROR" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Red"
            }
            Write-Host $logMessage -ForegroundColor $ForegroundColor
        }
    }

    if ($log) {
        Add-Content -Path $logFilePath -Value $logMessage
    }
}

function Write-Box {
    param (
        [string]$title
    )
    
    # Calculate the length of the title
    $titleLength = $title.Length

    # Create the top and bottom lines
    $line = "-" * $titleLength

    # Print the box
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
    Write-Log "| $title |" -severity INFO -ForegroundColor Cyan
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
}

function Invoke-EPMRestMethod  {
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
        [object]$Body,
        [hashtable]$Headers
    )

    $apiDelaySeconds = 120
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            # Convert Error message to Powershell Object
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json
            }
            else {
                throw "API call failed. $_"
            }

            # Error: EPM00000AE - Too many calls per 2 minute(s). The limit is 10
            if ( $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                Write-Log $ErrorDetailsMessage.ErrorMessage ERROR
                Write-Log "Retrying in $apiDelaySeconds seconds..." WARN
                Start-Sleep -Seconds $apiDelaySeconds
                $retryCount++
            }
            else {
                throw "API call failed. ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
            }
        }
    }

    # If all retries fail, handle accordingly
    throw "API call failed after $RetryCount retries."
}

function Connect-EPM {
    <#
    .SYNOPSIS
    Connects to the EPM (Enterprise Password Vault) using the provided credentials and tenant information.

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
        [pscredential]$credential,  # Credential object containing the username and password
        [string]$epmTenant          # EPM tenant name
    )

    # Convert credential information to JSON for authentication
    $authBody = @{
        Username = $credential.UserName
        Password = $credential.GetNetworkCredential().Password
        ApplicationID = "Powershell"
    } | ConvertTo-Json

    $authHeaders = @{
        "Content-Type" = "application/json"
    }

    $response = Invoke-EPMRestMethod -URI "https://$epmTenant.epm.cyberark.com/EPM/API/Auth/EPM/Logon" -Method 'POST' -Headers $authHeaders -Body $authBody

    # Return a custom object with connection information
    [PSCustomObject]@{
        managerURL = $($response.ManagerURL)
        auth       = $($response.EPMAuthenticationResult)
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

    .PARAMETER authToken
    The authorization token for authentication.

    .PARAMETER setName
    The name of the EPM set to retrieve.

    .OUTPUTS
    A custom object with the properties "setId" and "setName" representing the EPM set information.

    #>
    param (
        [string]$managerURL,
        [hashtable]$Headers,
        [string]$setName
    )

    $sets = Invoke-EPMRestMethod -URI "$managerURL/EPM/API/Sets" -Method 'GET' -Headers $Headers
    
    $setId = $null

    # Check if $SetName is empty
    if ([string]::IsNullOrEmpty($setName)) {

        # Repeat until a valid set number is entered
        do {
            # List the available sets with numbers
            Write-Box "Available Sets:" INFO
            $numberSets = 0
            foreach ($set in $sets.Sets) {
                Write-Log "$($numberSets + 1). $($set.Name)" INFO DarkCyan
                $numberSets++
            }
        
            # Ask the user to choose a set by number
            $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"
        
            # Validate the chosen set number
            try {
                $chosenSetNumber = [int]$chosenSetNumber
        
                if ($chosenSetNumber -lt 1 -or $chosenSetNumber -gt $numberSets) {
                    Write-Log "Invalid set number. Please enter a number between 1 and $numberSets." ERROR
                } else {
                    # Set chosenSet based on the user's selection
                    $chosenSet = $sets.Sets[$chosenSetNumber - 1]
                    $setId = $chosenSet.Id
                    $setName = $chosenSet.Name
                }
            } catch {
                Write-Log "Invalid input. Please enter a valid number." ERROR
            }
        } until ($setId)
    }
    
    else {
        # List the sets with numbers
        foreach ($set in $sets.Sets) {
            # Check if setname matches with the configured set
            if ($set.Name -eq $SetName) {
                $setId = $set.Id
                break  # Exit the loop once the set is found
            }
        }
        if ([string]::IsNullOrEmpty($setId)) {
            Write-Log "$SetName : Invalid Set" ERROR
            return
        }
    }

    # Return a custom object with set information
    [PSCustomObject]@{
        setId   = $setId
        setName = $setName
    }
}

function Output-PolicyTarget {
    
    param (
        [Parameter(Mandatory = $true)]
        $policy        
    )

    $ExecutorType = @{
        0 = "Computer group"
        1 = "Single computer"
    }
    
    $AccountType = @{
        0 = "Group"
        1 = "Single"
        2 = "Manually entered"
        4 = "Azure user"
        5 = "Azure group"
        6 = "AD user"
        7 = "AD group"
        8 = "IdP user"
        9 = "IdP group"
    }

    if ($policy.Executors.Count -gt 0) {
        Write-Log " - Policy applied to the following EPM Computers or EPM Groups:" INFO
        $policyDetails.Policy.Executors | ForEach-Object {
            Write-Log " -- $($ExecutorType[($_.ExecutorType)]): $($_.Name)" INFO
        }
    }
    if ($policy.Accounts.Count -gt 0) {
        Write-Log " - Policy applied to the folowing Users or Groups:" INFO
        $policy.Accounts | ForEach-Object {
            Write-Log " -- $($AccountType[($_.AccountType)]): $($_.SamName)" INFO
        }
    }
    if ($policy.IncludeADComputerGroups.Count -gt 0) {
        Write-Log "Policy applied to the folowing AD Computer Groups:" INFO
        $policy.Accounts | ForEach-Object {
            Write-Log " -- $($AccountType[($_.AccountType)]): $($_.SamName)" INFO
        }
    }
    if ($policy.ExcludeADComputerGroups.Count -gt 0) {
        Write-Log "Policy excluded for the folowing AD Computer Groups:" INFO
        $policy.Accounts | ForEach-Object {
            Write-Log " -- $($AccountType[($_.AccountType)]): $($_.SamName)" INFO
        }
    }
}
#######

### Mappings
# Define your mappings

$supportedOS = @{
    0 = "No OS"
    1 = "Windows"
    2 = "macOS"
    3 = "Windows, macOS"
    4 = "Linux"
    6 = "macOS, Linux"
    7 = "Windows, macOS, Linux"
}
##########

### Script Functions

# Generic function to add parameters and nested settings to any specified root object

function Get-AdvancedParameters {
    param (
        [PSCustomObject]$paramObject    # The object to inspect
    )

    # Initialize a variable to accumulate the string
    $output = ""

    foreach ($param in $paramObject.PSObject.Properties){
        if ($param.Value -is [PSCustomObject]) {
            $output += "$($param.Name):["
            $output += Get-PSCustomObjectProperties -paramObject $param.Value
            $output = $output.TrimEnd(', ')
            $output += "]"                                            
        } else {
            $output += "$($param.Name): $($param.Value), "
        }
    } 
    $output = $output.TrimEnd(', ')
    return $output
}

function Get-AdvancedParametersHTML {
    param (
        [PSCustomObject]$paramObject    # The object to inspect
    )

    # Initialize a variable to accumulate the string
    $output = "<ul>"

    foreach ($param in $paramObject.PSObject.Properties){
        if ($param.Value -is [PSCustomObject]) {
            $output += "<li>$($param.Name)"
            $output += Get-AdvancedParametersHTML -paramObject $param.Value
            $output += "</li>"
        } elseif ($param.Value -is [Array]) {
            $output += "<li>$($param.Name):</li>"
            $output += "<ul>"
            $output += ($param.Value | ForEach-Object { "<li>$($_)</li>" }) -join "`n"
            $output += "</ul>"
        } else {
            $output += "<li>$($param.Name): $($param.Value)</li>`n"
        }
    } 
    $output += "</ul>"
    return $output
}

# Function to process FileTypesToScanForApplicationCatalog
function Get-FileTypesToScanForApplicationCatalog {
    param (
        [string]$ParamName,
        [array]$ParamValue
    )

    $FileTypesToScanForApplicationCatalogMappings = @{
        ExecutableExtensions = @{
            0 = "EXE"
            1 = "COM"
            2 = "SCR"
        }
        InstallationPackageExtensions = @{
            0 = "MSI"
            1 = "MSP"
            2 = "MSU"
        }
        DLLExtensions = @{
            0 = "ACM"
            1 = "AX"
            2 = "CPL"
            3 = "DLL"
            4 = "EFI"
            5 = "FON"
            6 = "FOT"
            7 = "ICL"
            8 = "IME"
            9 = "MUI"
            10 = "OCX"
            11 = "SHS"
            12 = "VBX"    
        }
        ScriptFileExtensions = @{
            0 = "BAT"
            1 = "CMD"
            2 = "VBS"
            3 = "VBE"
            4 = "HTA"
            5 = "JS"
            6 = "JSE"
            7 = "WSF"
            8 = "WSH"
            9 = "PS1"
            10 = "REG"
            11 = "PDF"
        }
        MacInstallationExtensions = @{
            0 = "DMG"
            1 = "PKG"
            2 = "MPKG"
        }
    }
    
    # Check if the parameter is the MacAllExecutableFiles Boolean
    if ($ParamName -eq "MacAllExecutableFiles") {
        # If it's a Boolean, display "ON" or "OFF"
        if ($ParamValue) { return "ON" } else { return "OFF" }
    }
    # Check if the parameter has a mapped dictionary and is an array
    elseif ($FileTypesToScanForApplicationCatalogMappings.ContainsKey($ParamName) -and $ParamValue -is [Array]) {
        $mapping = $FileTypesToScanForApplicationCatalogMappings[$ParamName]
        
        # Map each number in the array to its display value
        return ($ParamValue | ForEach-Object {
            if ($mapping.ContainsKey($_)) {
                return $mapping[$_]
            } else {
                "Unknown"
            }
        }) -join ", "
    }
    # If the parameter is not recognized or doesn't have mapped values
    else {
        return "No Value"
    }
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
##

Write-Box "$scriptName"
##

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

Write-Box "$($set.setName)"
<#
# Get Default policy

$policiesSearchFilter = @{
    "filter" = "policyGroupType EQ 7"
} | ConvertTo-Json

$policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter

# Analyze Policy result

$policyTypes = @{
    1 =	"Privilege Management Detect"
    2 = "Application Control Detect"
    3 =	"Application Control Restrict"
    4 = "Ransomware Protection Detect"
    5 = "Ransomware Protection Restrict"
    6 =	"INT Detect"
    7 = "INT Restrict"
    8 =	"INT Block"
    9 =	"Privilege Management Elevate"
    10 = "Application Control Block"
    11 = "Advanced Windows"
    12 = "Advanced Linux"
    13 = "Advanced Mac"
    14 = "Application Group Win"
    15 = "Application Group Linux"
    16 = "Application Group Win"
    17 = "Recommended Block Windows OS Applications"
    18 = "Predefined App Groups Win"
    19 = "Microsoft Windows Programs (Win Files)"
    20 = "Developer Applications"
    21 = "Authorized Applications (Ransomware)"
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
    33 = "Trusted Distributor Predefined Definition Win"
    34 = "Trusted Updater Predefined Definition Win"
    35 = "Trusted Distributor Predefined Definition Mac"
    36 = "User Policy - Set Security Permissions for File System and Registry Keys"
    37 = "User Policy - Set Security Permissions for Services"
    38 = "User Policy - Set Security Permissions for Removable Storage (USB, Optical Discs)"
    39 = "Collect UAC actions by Local Admin"
    40 = "JIT Access and Elevation"
    41 = "Deploy Script"
    42 = "Execute Script"
    43 = "Predefined App Groups Win"
    45 = "Agent Configuration"
    46 = "Remove Admin"
    47 = "Deception"
}

$PMDetectNotification = @{
    0 = "Suppress OS Native Notification"
    1 = "Allow OS Notification"
    2 = "Use EPM Notification"
}

foreach ($policy in $policySearch.Policies) {
    if ($policy.isActive -eq $true) {
        $policyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.policyId)" -Method 'GET' -Headers $sessionHeader
        switch ($policy.PolicyType) {
            # [PM Detect]
            1 { 
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                Write-Log " - Detection mode (Windows only): $($policyDetails.Policy.DetectUserActionsOnly)" INFO
                Write-Log " - Standard end users:" INFO
                Write-Log " -- Detect unhandled applications when administrative privileges are required: $($policyDetails.Policy.DetectEvents4StdUsers)" INFO
                Write-Log " -- Prompt end users when an unhandled application requires administrative privileges: $($PMDetectNotification[$($policyDetails.Policy.PMDetectStdNotificationMode)])" INFO
                if ($policyDetails.Policy.PMDetectStdNotificationMode -eq 2) {
                    Write-Log " --- Windows Dialog: $($policyDetails.Policy.PMDetectStdWinNotification.AllowedDialogType)" INFO
                    Write-Log " --- macOS Dialog: $($policyDetails.Policy.PMDetectStdMacNotification.AllowedDialogType)" INFO
                    Write-Log " --- Linux Dialog: $($policyDetails.Policy.PMDetectStdLinuxNotification.AllowedDialogType)" INFO
                }
                Write-Log " - Administrative end users:" INFO
                Write-Log " -- Detect unhandled applications when administrative privileges are required: $($policyDetails.Policy.DetectEvents4AdmUsers)" INFO
                Write-Log " -- Notify end users when an unhandled application requires administrative privileges: $($PMDetectNotification[$($policyDetails.Policy.PMDetectAdmNotificationMode)])" INFO
                if ($policyDetails.Policy.PMDetectStdNotificationMode -eq 2) {
                    Write-Log " --- Windows Dialog: $($policyDetails.Policy.PMDetectAdmWinNotification.AllowedDialogType)" INFO
                    Write-Log " --- macOS Dialog: $($policyDetails.Policy.PMDetectAdmMacNotification.AllowedDialogType)" INFO
                    Write-Log " --- Linux Dialog: $($policyDetails.Policy.PMDetectAdmLinuxNotification.AllowedDialogType)" INFO
                }
                Write-Log " - Detect unsuccessful application launches using heuristics (Windows only): $($policyDetails.Policy.DetectHeuristics)" INFO
                if ($policyDetails.Policy.DetectHeuristics -eq $true) {
                    Write-Log " -- Prompt users when an application is elevated manually: $($policyDetails.Policy.PMDetectHeuristicsNotification.AllowedDialogType)" INFO
                }
                Write-Log " - Allow end users to submit elevation requests (Windows, macOS): $($policyDetails.Policy.ManualRequests)" INFO
                if ($policyDetails.Policy.ManualRequests -eq $true) {
                    Write-Log " -- Prompt users when an application is elevated manually: $($policyDetails.Policy.PMDetectManualNotification.AllowedDialogType)" INFO
                }
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy                }
                }
            # [AC Detect]
            2 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                Write-Log " - Detect launch of unhandled applications: $($policyDetails.policy.DetectLaunches)" INFO
                if ($policyDetails.Policy.DetectLaunches.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unhandled application is launched (Windows only): $($policyDetails.Policy.ACLaunchWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unhandled application is launched (Windows only): OFF" INFO
                }
                Write-Log " - Detect installation of unhandled applications (Windows only): $($policyDetails.policy.DetectInstallations)" INFO
                Write-Log " - Detect access to sensitive resources by unhandled applications: $($policyDetails.policy.DetectAccess)" INFO
                Write-Log " - Include applications installed before the EPM agent: $($policyDetails.policy.Apply2OldApps)" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            # [AC Restrict]
            3 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)]) (Windows and macOS)" INFO
                Write-Log " - Detect launch of unhandled applications: $($policyDetails.policy.DetectLaunches)" INFO
                if ($policyDetails.Policy.IntLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " -- Notify end users when an unhandled application is launched: $($policyDetails.Policy.ACLaunchWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " -- Notify end users when an unhandled application is launched: OFF" INFO
                }
                Write-Log " - Detect installations of unhandled applications: $($policyDetails.policy.DetectInstallations)" INFO
                Write-Log " - Restriction" INFO
                Write-Log " -- Restriction - Internet: $($policyDetails.policy.RestrictAccessInternet)" INFO
                Write-Log " -- Restriction - Intranet: $($policyDetails.policy.RestrictAccessIntranet)" INFO
                Write-Log " -- Restriction - Network shares: $($policyDetails.policy.RestrictAccessShares)" INFO
                Write-Log " -- Restriction - Memory of other processes: $($policyDetails.policy.RestrictAccessRAM)" INFO
                if ($policyDetails.Policy.ACRestrictAccessWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs (Windows): $($policyDetails.Policy.ACRestrictAccessWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs (Windows): OFF" INFO
                }
                if ($policyDetails.Policy.ACRestrictAccessMacNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs (macOS): $($policyDetails.Policy.ACRestrictAccessMacNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs (macOS): OFF" INFO
                }              
                Write-Log " - Include applications installed before the EPM agent: $($policyDetails.policy.Apply2OldApps)" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            # [RP Detect]
            4 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            # [RP Restrict]
            5 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            # [Internet Detect]
            6 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)]) (Windows only)" INFO
                Write-Log " - Detect launch of unhandled applications downloaded from the internet: $($policyDetails.policy.DetectLaunches)" INFO
                if ($policyDetails.Policy.IntLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unhandled application is launched: $($policyDetails.Policy.IntLaunchWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unhandled application is launched: OFF" INFO
                }
                Write-Log " - Detect installation of unhandled applications downloaded from the internet: $($policyDetails.policy.DetectInstallations)" INFO
                Write-Log " - Detect access to the sensitive resources by unhandled applications downloaded from the internet: $($policyDetails.policy.DetectAccess)" INFO
                Write-Log " - Include applications installed before the EPM agent: $($policyDetails.policy.Apply2OldApps)" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }             
            # [Internet Restrict]
            7 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)]) (Windows only)" INFO
                Write-Log " - Detect launch of unhandled applications downloaded from the internet: $($policyDetails.policy.DetectLaunches)" INFO
                if ($policyDetails.Policy.IntLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unhandled application is launched: $($policyDetails.Policy.ACLaunchWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unhandled application is launched: OFF" INFO
                }
                Write-Log " - Detect installations of unhandled applications downloaded from the internet: $($policyDetails.policy.DetectInstallations)" INFO
                Write-Log " - Restriction" INFO
                Write-Log " -- Restriction - Internet: $($policyDetails.policy.RestrictAccessInternet)" INFO
                Write-Log " -- Restriction - Intranet: $($policyDetails.policy.RestrictAccessIntranet)" INFO
                Write-Log " -- Restriction - Network shares: $($policyDetails.policy.RestrictAccessShares)" INFO
                Write-Log " -- Restriction - Memory of other processes: $($policyDetails.policy.RestrictAccessRAM)" INFO
                if ($policyDetails.Policy.IntRestrictAccessWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs: $($policyDetails.Policy.IntRestrictAccessWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end users when an unauthorized access attempt occurs: OFF" INFO
                }                
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            # [Internet Block]
            8 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                Write-Log " -- Detect attempts to launch unhandled applications downloaded from the internet: $($policyDetails.policy.SendBlockEvent)" INFO
                if ($policyDetails.Policy.IntBlockWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Notify end user when unhandled application downloaded from the internet is blocked (Windows only): $($policyDetails.Policy.IntBlockWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Notify end user when unhandled application downloaded from the internet is blocked (Windows only): OFF" INFO
                }
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }                
            }
            # [PM Elevate]
            9 { 
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
                Write-Log " - Standard end users:" INFO
                Write-Log " -- Elevate unhandled applications when privileges are required: $($policyDetails.Policy.Elevate4StdUsers)" INFO
                if ($policyDetails.Policy.PMElevateStdWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Windows Dialog: $($policyDetails.Policy.PMElevateStdWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Windows Dialog: OFF" INFO
                }
                if ($policyDetails.Policy.PMElevateStdMacNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- macOS Dialog: $($policyDetails.Policy.PMElevateStdMacNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- macOS Dialog: OFF" INFO
                }
                if ($policyDetails.Policy.PMElevateStdLinuxNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Linux Dialog: $($policyDetails.Policy.PMElevateStdLinuxNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Linux Dialog: OFF" INFO
                }
                
                Write-Log " - Administrative end users:" INFO
                Write-Log " -- Detect unhandled applications when administrative privileges are required: $($policyDetails.Policy.Elevate4AdmUsers)" INFO
                if ($policyDetails.Policy.PMElevateAdmWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Windows Dialog: $($policyDetails.Policy.PMElevateAdmWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Windows Dialog: OFF" INFO
                }
                if ($policyDetails.Policy.PMElevateAdmMacNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- macOS Dialog: $($policyDetails.Policy.PMElevateAdmMacNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- macOS Dialog: OFF" INFO
                }
                if ($policyDetails.Policy.PMElevateAdmLinuxNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " --- Linux Dialog: $($policyDetails.Policy.PMElevateAdmLinuxNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " --- Linux Dialog: OFF" INFO
                }

                Write-Log " - Detect unsuccessful application launches using heuristics (Windows only): $($policyDetails.Policy.DetectHeuristics)" INFO
                Write-Log " - Allow end users to submit elevation requests (Windows, macOS): $($policyDetails.Policy.ManualRequests)" INFO
                if ($policyDetails.Policy.ManualRequests -eq $true) {
                    if ($policyDetails.Policy.PMElevateManualNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                        Write-Log " --- Prompt users when an application is elevated manually: $($policyDetails.Policy.PMElevateManualNotification.AllowedDialogType)" INFO
                    } else {
                        Write-Log " --- Prompt users when an application is elevated manually: OFF" INFO
                    }                    
                }
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy                }
            }
            # [AC Block]
            10 {
                Write-Box "$($policyTypes[$($policyDetails.Policy.PolicyType)]) (Windows and macOS)" INFO
                Write-Log " - Detect attempts to launch unhandled applications: $($policyDetails.policy.SendBlockEvent)" INFO
                if ($policyDetails.Policy.ACBlockWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " -- Notify users when an unhandled application is blocked (Windows): $($policyDetails.Policy.ACBlockWinNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " -- Notify users when an unhandled application is blocked (Windows): OFF" INFO
                }
                if ($policyDetails.Policy.ACBlockMacNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    Write-Log " -- Notify users when an unhandled application is blocked (macOS): $($policyDetails.Policy.ACBlockMacNotification.AllowedDialogType)" INFO
                } else {
                    Write-Log " -- Notify users when an unhandled application is blocked (macOS): OFF" INFO
                }
                Write-Log " - Include applications installed before the EPM agent: $($policyDetails.policy.Apply2OldApps)" INFO
                Write-Log " - Include controlled Windows OS programs (Windows Only): $($policyDetails.policy.Apply2WindowsPrograms)" INFO
                if ($policyDetails.Policy.IsAppliedToAllComputers -eq $true) {
                    Write-Log " - Policy Applied to all Computers" INFO
                } else {
                    Output-PolicyTarget $policyDetails.policy
                }
            }
            Default {}
        }

        #$policyDetails | ConvertTo-Json
    }
    

}
#>
# Get Agent Configuration

Write-Box "Getting Advanced Agent General Configuration"
$agentConfGeneral = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration/$($set.setId)" -Method 'GET' -Headers $sessionHeader

# HTML structure
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Configuration</title>
    <!-- Include Titillium Web font from Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Titillium+Web:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        /* Apply the Titillium Web font */
        body {
            font-family: 'Titillium Web', sans-serif;
            line-height: 1.6;
        }
        h1 {
            text-align: center;
            color: #333;
            font-weight: 600;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        /* Header color: Turquoise */
        th {
            background-color: turquoise;
            color: white;
            font-weight: 600;
        }
        /* Even row color: rgb(199, 221, 236) */
        tr:nth-child(even) {
            background-color: rgb(199, 221, 236);
        }
        /* Odd row color: rgb(167, 201, 225) */
        tr:nth-child(odd) {
            background-color: rgb(167, 201, 225);
        }
        /* Add hover effect for rows */
        tr:hover {
            background-color: #f1f1f1;
        }
    </style>
</head>
<body>
<h1>Agent Configuration</h1>
<table>
<tr>
<th>ParameterType</th>
<th>Parameter</th>
<th>OS</th>
<th>Settings</th>
</tr>
"@

$validOptions = @(
    "ExtendedProtection",
    "DataCollection",
    "Policies",
    "EndpointUi",
    "StepUpAuthentication",
    "CloudEnvironments",
    "OfflinePolicyAuthorizationGenerator",
    "VideoRecording",
    "AgentBehavior"
)

foreach ($agentParamType in $agentConfGeneral.Policy.PSObject.Properties) {
    
    if ($validOptions -contains $agentParamType.Name) {
        Write-Log " + $($agentParamType.Name)" INFO
        
        foreach ($agentParam in $agentParamType.Value.PSObject.Properties){
            # Reset the variables
            $setting = ""
            $settingHTML = ""
            $paramHTML = ""
            # Define the OS
            $OS = $($supportedOS[$($agentParam.Value.SupportedOS)])

            if ($agentParam.Name -eq "SupportInfoFilePasswordDefault") {
                continue # Skip this value
            }
            
            if ($agentParam.Value.Value -is [Boolean] -or
                $agentParam.Value.Value -is [String] -or
                $agentParam.Value.Value -is [Int32]) {
                switch ($agentParam.Value.Value) {
                    ""         { $setting = "No Value" }
                    $true      { $setting = "ON" }
                    $false     { $setting = "OFF" }
                    default    { $setting = $agentParam.Value.Value }
                }
                #Add-Parameter -rootObject $AgentConfig -parameterTypeName $($agentParamType.Name) -parameterName $($agentParam.Name) -settingName $setting -OS $OS
                $settingHTML = "$setting"
            } elseif ($agentParam.Value.Value -is [PSCustomObject]) {
                if ($agentParam.Name -eq "ThreatProtectionExcludedApplications" -or
                    $agentParam.Name -eq "ExcludeNewFilesFromTheApplicationCatalogAndInbox" -or
                    $agentParam.Name -eq "ExcludeFilesFromProtectionMacos" -or
                    $agentParam.Name -eq "ExcludeFilesFromProtectionWindows") {
                    if ($null -eq $agentParam.Value.Value.Applications -or $agentParam.Value.Value.Applications.Count -eq 0) {
                        # Array is empty
                        $setting = "No Value"
                        $settingHTML = "$setting"
                    } else {
                        # Process Array 
                        $setting = ($agentParam.Value.Value.Applications | ForEach-Object { $_.displayName }) -join ", "
                        $settingHTML = "<ul>" + ($agentParam.Value.Value.Applications | ForEach-Object { "<li>$($_.displayName)</li>" }) -join "`n" + "</ul>"
                    }
                    
                } elseif ($agentParam.Name -eq "FileTypesToScanForApplicationCatalog" ) {
                    foreach ($property in $agentParam.Value.Value.PSObject.Properties) {
                        $returnFileType = Get-FileTypesToScanForApplicationCatalog -ParamName $property.Name -ParamValue $property.Value
                    
                        $setting += "$($property.Name): $returnFileType - "
                        $paramHTML += "<li>$($property.Name): $returnFileType</li>`n"
                    }
                    $settingHTML = "<ul>$paramHTML</ul>"
                } else {
                    $setting = Get-AdvancedParameters -paramObject $agentParam.Value.Value
                    $settingHTML = Get-AdvancedParametersHTML -paramObject $agentParam.Value.Value
                }

            } elseif ($agentParam.Value.Value -is [array]) {
                if ($null -eq $agentParam.Value.Value -or $agentParam.Value.Value.Count -eq 0) {
                    # Array is empty
                    $setting = "No Value"
                    $settingHTML = "$setting"
                } else {
                    # Array has data, join elements with a comma
                    $setting = $agentParam.Value.Value -join ", "
                    #$settingHTML = $setting -replace ", ", "<br>"
                    $paramHTML = "<ul>" + ($agentParam.Value.Value | ForEach-Object { "<li>$_</li>" }) -join "`n" + "</ul>"
                    $settingHTML = "$paramHTML"
                }
                
            } else {
                $setting = $agentParam.Value.Value.GetType().Name
                $settingHTML = "$setting"
            }
            
            Write-Log " + - $($agentParam.Name) - $OS - $setting" INFO
            $htmlContent += "<tr><td>$($agentParamType.Name)</td><td>$($agentParam.Name)</td><td>$OS</td><td>$settingHTML</td></tr>"
        }
    }
}

# End HTML structure
$htmlContent += @"
</table>
</body>
</html>
"@

# Output to HTML file
Write-Log "Write HTML" INFO
$htmlFilePath = "AgentConfig_Report.html"
$htmlContent | Out-File -FilePath $htmlFilePath -Encoding UTF8

<#
Write-Log " + Extended Protection" INFO
Write-Log " + - Agent self-defense - $($supportedOS[$($agentConfGeneral.Policy.ExtendedProtection.AgentSelfDefense.SupportedOS)]) - $($agentConfGeneral.Policy.ExtendedProtection.AgentSelfDefense.value)" INFO
Write-Log " + - Support info file password - $($supportedOS[$($agentConfGeneral.Policy.ExtendedProtection.SupportInfoFilePassword.SupportedOS)]) - $($agentConfGeneral.Policy.ExtendedProtection.SupportInfoFilePassword.value)" INFO
Write-Log " + - Protect administrative user groups - " INFO
Write-Log "Anti-tampering protection" INFO
Write-Log "Protect elevated processes from DLL hijacking - $($supportedOS[$($agentConfGeneral.Policy.ExtendedProtection.ProtectElevatedProcessesFromDllHijacking.SupportedOS)]) - $($agentConfGeneral.Policy.ExtendedProtection.ProtectElevatedProcessesFromDllHijacking.value)" INFO
Write-Log " + Data collection" INFO
Write-Log " + - Collect policy audit data - $($supportedOS[$($agentConfGeneral.Policy.DataCollection.CollectPolicyAuditData.SupportedOS)]) - $($agentConfGeneral.Policy.DataCollection.CollectPolicyAuditData.value)" INFO
Write-Log "Exclude new files from the Application Catalog and Events Management" INFO
Write-Log "File types to scan for Application Catalog" INFO
Write-Log "Event queue flush period" INFO
Write-Log "Policy audit event flush period" INFO
Write-Log "Threat protection event queue flush period" INFO
Write-Log "Collect events in event log" INFO
Write-Log "Collect events in WMI" INFO
Write-Log "Collect temporary files" INFO
Write-Log "Collect events triggered by service accounts" INFO
Write-Log "Collect child command events" INFO
Write-Log "Report user groups in events" INFO
Write-Log "Collect protected accounts" INFO
Write-Log "Policies" INFO
Write-Log "Enable policy suspension" INFO
Write-Log "Confirm elevation" INFO
Write-Log " + - Threat protection excluded applications - $($supportedOS[$($agentConfGeneral.Policy.DataCollection.ThreatProtectionExcludedApplications.SupportedOS)]) - $($agentConfGeneral.Policy.DataCollection.ThreatProtectionExcludedApplications.value)" INFO
Write-Log "Heartbeat timeout" INFO
Write-Log "Policy condition timeout" INFO
Write-Log "Script timeout" INFO
Write-Log "Policy update interval" INFO
Write-Log "Refresh Windows desktop after policy update" INFO
Write-Log "Trace policy usage on agents" INFO
Write-Log "Well known publishers" INFO
Write-Log "Exclude service accounts from access restrictions" INFO
Write-Log "Elevate SCCM ""for user"" installations" INFO
Write-Log "Restrict CMD special characters" INFO
Write-Log "Allowed interpreters" INFO
Write-Log "Environment variables" INFO
Write-Log "Agent behavior" INFO
Write-Log "Exclude files from policies (Windows)" INFO
Write-Log "Exclude files from policies (macOS)" INFO
Write-Log "Monitor system processes" INFO
Write-Log "Store file info in extended attributes" INFO
Write-Log "Enable DLL support" INFO
Write-Log "Verify digital signature on scripts" INFO
Write-Log "Discover source URL" INFO
Write-Log "Discover source email" INFO
Write-Log "Support network shares" INFO
Write-Log "Boot-start driver" INFO
Write-Log "Monitor SIP files" INFO
Write-Log "Allow root permission for root programs" INFO
Write-Log "Sudo grace validation period" INFO
Write-Log "Prevent sudoers file modification" INFO
Write-Log "Trace new files" INFO
Write-Log "Sudo no password" INFO
Write-Log "Sudo secure path" INFO
Write-Log "Allowed preloader" INFO
Write-Log "Allow sudoers interoperability" INFO
Write-Log "Endpoint UI" INFO
Write-Log "Show icon in task/menu bar" INFO
Write-Log "Show CyberArk EPM tab in File Properties" INFO
Write-Log "Show CyberArk EPM Control Panel on desktop" INFO
Write-Log "Hide Windows ""Run As..."" menu items" INFO
Write-Log "Hide CyberArk EPM agent from installed programs" INFO
Write-Log "Shell elevate menu text" INFO
Write-Log "Enable tabbed browsing" INFO
Write-Log "IdP settings" INFO
Write-Log "CyberArk Identity " INFO
Write-Log "Custom identity provider" INFO
Write-Log "Cloud environments" INFO
Write-Log "Enable Azure Active Directory" INFO
Write-Log "Offline policy authorization generator" INFO
Write-Log "Enable Offline Policy Authorization Generator" INFO
Write-Log "Enable 'Run with Authorization token'" INFO
Write-Log "Audit video configuration" INFO
Write-Log "Allow application to run if recording is unavailable" INFO
Write-Log "Maximum movie length" INFO
Write-Log "Video file retention period" INFO
Write-Log "Video file destination" INFO
#>

# Destination File Name
# $policyFileName = "$($setName)_$($getPolicyObj.Name).json" -replace "\[|\]|:"
# $policyPath = "$($folder)\$($policyFileName)"

# Store policy in JSON file
# $getPolicyObj | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Force
# Write-Host "$($getPolicyObj.Name) saved to $($policyPath)" -ForegroundColor Green
