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
    [string]$tenant
)
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
        Write-Log "Policy Name: $($policy.PolicyName)" INFO
        $policyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.policyId)" -Method 'GET' -Headers $sessionHeader
        if ($policy.PolicyName -match '\[PM .*\]') {
            Write-Log " - $($policyTypes[$($policyDetails.Policy.PolicyType)])" INFO
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
            if ($policyDetails.IsAppliedToAllComputers -eq $true) {
                Write-Log " - Policy Applied to all Computers" INFO
            } else {
                if ($policyDetails.Policy.Executors.Count -gt 0) {
                    Write-Log "Policy applied to the following EPM Computers or EPM Groups:" INFO
                    $policyDetails.Policy.Executors | ForEach-Object {
                        Write-Log "EPM Object: $_" INFO
                    }
                }
                if ($policyDetails.Policy.Accounts.Count -gt 0) {
                    Write-Log "Policy applied to the folowing Users or Groups:" INFO
                    $policyDetails.Policy.Accounts | ForEach-Object {
                        Write-Log "User: $_" INFO
                    }
                }
                if ($policyDetails.Policy.IncludeADComputerGroups.Count -gt 0) {
                    Write-Log "Policy applied to the folowing AD Computer Groups:" INFO
                    $policyDetails.Policy.Accounts | ForEach-Object {
                        Write-Log "AD Computer Group: $_" INFO
                    }
                }
            }

        }
        
        #$policyDetails | ConvertTo-Json
    }
    

}





<# OLD Approach: analyze the vf_policy.xml file
param (
    [Parameter(Mandatory = $true)]
    [string]$xmlFilePath
)

function checkUACStatus {
    param (
        $policyString,
        
        [ValidateSet("user", "admin")]
        $userType
    )

    if ($userType -eq "user") {
        if ($policyString.replaceUAC -eq $true -or $policyString.suppressUAC -eq $true) {
            return "Standard end users: Elevate unhandled applications when privileges are required"
        } else {
            return "Standard end users: Not enabled"
        }
    } elseif ($userType -eq "admin") {
        if ($policyString.replaceAdminUAC -eq $true -or $policyString.suppressAdminUAC -eq $true) {
            return "Administrative end users: Elevate unhandled applications when privileges are required"
        } else {
            return "Administrative end users: Not enabled"
        }
    }
}


# Load the XML file
if (-Not (Test-Path $xmlFilePath)) {
    Write-Error "File not found: $xmlFilePath"
    exit
}
[xml]$xmlContent = Get-Content $xmlFilePath

$appCtrlDefaultPolicyMap = @{
    3   = "Block"
    256 = "Monitor"
    2   = "Restrict"
}

# Initialize empty arrays to store results
$defaultPolicies = @()
$threatProtectionPolicies = @()
$defaultPoliciesResult = [PSCustomObject]@{
    PrivManagement = [PSCustomObject]@{
        Status = "No data Found"
        Users  = "No data Found"
        Admins = "No data Found"
        sourceUser = "No data Found"
        collectUserActionsOnly = "No data Found"
        collectUserReq = "No data Found"
        useHeuristics = "No data Found"
    }
    Ransomware = "No data Found"
    InternetControl = "No data Found"
    AppControl =  [PSCustomObject]@{
        Status = "No data Found"
        reportProcLaunches = "No data Found"

    }
}

# Parse the XML and the default policies details
foreach ($policy in $xmlContent.Policies.Policy) {
    if ([int]$policy.order -ge 4090 -and $policy.sendPolicyAutomation -eq $true) {
        # Collect all necessary information for default policy
        $defaultPolicyDetails = [PSCustomObject]@{
            ID                          = $policy.id                        
            Order                       = $policy.order
            Name                        = $policy.name
            Action                      = $policy.action
            ReportUsage                 = $policy.reportUsage
            Implicit                    = $policy.implicit
            InternalType                = $policy.internalType
            SendPolicyAutomation        = $policy.sendPolicyAutomation
            CollectUserActionsOnly      = $policy.collectUserActionsOnly
            UseHeuristics               = $policy.useHeuristics
            SuppressUAC                 = $policy.suppressUAC
            SuppressAdminUAC            = $policy.suppressAdminUAC
            SourceUser                  = $policy.sourceUser
            CollectUserReq              = $policy.collectUserReq
            restrictionId               = $policy.restrictionId                 #AppCtrl
            reportProcLaunches          = $policy.reportProcLaunches            #AppCtrl
            internalDefaultPolicyModeAC = $policy.internalDefaultPolicyModeAC   #AppCtrl
        }
        $defaultPolicies += $defaultPolicyDetails
        
        # Detect Application policy (Privilege Managent and Application control)
        if ($policy.name -match '.*Windows Main Default Policy.*'){
            if ($policy.action -eq "6") {
                $defaultPoliciesResult.PrivManagement.Status = 'ON'
                switch ([int]$policy.sourceUser) {
                    0 { 
                        $defaultPoliciesResult.PrivManagement.Users = checkUACStatus $policy user
                        $defaultPoliciesResult.PrivManagement.Admins = "Disabled"
                    }
                    1 {
                        $defaultPoliciesResult.PrivManagement.Users = "Disabled"
                        $defaultPoliciesResult.PrivManagement.Admins = checkUACStatus $policy admin
                    }
                    2 {
                        $defaultPoliciesResult.PrivManagement.Users = checkUACStatus $policy user
                        $defaultPoliciesResult.PrivManagement.Admins = checkUACStatus $policy admin
                    }
                    default { Write-Host "Unknown case" }
                }
                $defaultPoliciesResult.PrivManagement.useHeuristics = $policy.useHeuristics
                $defaultPoliciesResult.PrivManagement.collectUserReq = $policy.collectUserReq
                $defaultPoliciesResult.PrivManagement.collectUserActionsOnly = $policy.collectUserActionsOnly
                
                $defaultPoliciesResult.AppControl.Status = $appCtrlDefaultPolicyMap[[int]$policy.internalDefaultPolicyModeAC]
                $defaultPoliciesResult.AppControl.reportProcLaunches = $policy.reportProcLaunches

            } elseif ($policy.action -eq "1") {
                $defaultPoliciesResult.PrivManagement.Status = 'OFF'
            } elseif ($policy.action -eq "4") {
                if ($policy.name -match '.*Windows Main Default Policy.*'){
                    $defaultPoliciesResult.PrivManagement.Status = 'ELEVATE'
                    if ($policy.replaceUAC -eq $true) {
                        $defaultPoliciesResult.PrivManagement.Users = "Standard end users: Elevate unhandled applications when privileges are required"
                    } else {
                        $defaultPoliciesResult.PrivManagement.Users = "Standard end users: Not enabled"
                    }
                    if ($policy.replaceAdminUAC -eq $true) {
                        $defaultPoliciesResult.PrivManagement.Admins = "Administrative end users: Elevate unhandled applications when privileges are required"
                    } else {
                        $defaultPoliciesResult.PrivManagement.Admins = "Administrative end users: Not enabled"
                    }
                }
            } 
        }
    }
<#
        # Analyze Applications
        if ($policy.name -match '\[AppCtrl.*') {
            # Detect Ransomware
            if ($policy.name -match '.*Ransomware.*') {
                if ($policy.name -match '\[AppCtrl\s+(\w+):') {
                    $action = $Matches[1]
                    $defaultPoliciesResult.Ransomware = $action
                } else {
                    $defaultPoliciesResult.Ransomware = 'No data Found'
                }
            }
            # Detect Application Control
            if ($policy.name -match '.*Windows Main Default Policy*') {
                if ($policy.name -match '\[AppCtrl\s+(\w+):') {
                    $action = $Matches[1]
                    $defaultPoliciesResult.AppControl = $action
                } else {
                    $defaultPoliciesResult.AppControl = 'No data Found'
                }
           }
        }
        # Analyze Internet Control
        if ($policy.name -match '\[Internet.*') {
            if ($policy.name -match '.*Windows Main Default Policy*') {
                if ($policy.name -match '\[Internet\s+(\w+):') {
                    $action = $Matches[1]
                    $defaultPoliciesResult.InternetControl = $action
                }
                else {
                    $defaultPoliciesResult.InternetControl = 'No data Found'
                }
            }
        }
    }
    elseif ($policy.action -eq "15") {
        # Collect all necessary information for action 15
        $threatProtectionDetails = [PSCustomObject]@{
            ID         = $policy.id
            Order      = $policy.order
            Name       = $policy.name
            ThreatID   = $policy.threatID
            EPAction   = $policy.epAction
        }
        $threatProtectionPolicies += $threatProtectionDetails
    }

}

# Output the results in a readable format
Write-Host "Defautl Policies:"
$defaultPolicies | Format-Table -AutoSize
Write-Host "Detect privileged unhandled applications [Windows][macOS][Linux] = $($defaultPoliciesResult.PrivManagement.Status)"
Write-Host " - $($defaultPoliciesResult.PrivManagement.Users)"
Write-Host " - $($defaultPoliciesResult.PrivManagement.Admins)"
Write-Host " - Detect unsuccessful application launches using heuristics (Windows only): $($defaultPoliciesResult.PrivManagement.UseHeuristics)"
Write-Host " - Allow user to manually request privilege elevation: $($defaultPoliciesResult.PrivManagement.collectUserReq)"
Write-Host " - Collect only events triggered by end-user actions. Skip events triggered by system, scheduled tasks etc.: $($defaultPoliciesResult.PrivManagement.collectUserActionsOnly)"

Write-Host "Control unhandled applications [Windows][macOS] = $($defaultPoliciesResult.AppControl.Status)"
Write-Host " - Detect launch of unhandled applications = $($defaultPoliciesResult.AppControl.reportProcLaunches)"
#Write-Host $defaultPoliciesResult.AppControl.Status
#Write-Host "Protect against ransomware [Windows] = $($defaultPoliciesResult.Ransomware)"
#Write-Host "Control unhandled applications downloaded from the internet [Windows] = $($defaultPoliciesResult.InternetControl)"
#Write-Host "Control unhandled applications [Windows][macOS] = $($defaultPoliciesResult.AppControl)"

#$action6Policies | ConvertTo-Csv



#foreach ($action6Detail in $action6Detail) {
#    if ($action6Detail.name -contains "Detect")
#}



#Write-Host "`nPolicies with action='15':"
#$action15Policies | Format-Table -AutoSize
#>