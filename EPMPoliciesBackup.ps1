<#
.SYNOPSIS
    Backup Policies and configuration

.DESCRIPTION
    Save all policies (Default, Advanced, Application), Application Groups and Advanced Configuration
    The script is ready to use an inclremental backup mode, uncomment "incremental backup" to enabled  
    
.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.NOTES
    File: EPMPoliciesBackup.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.3 - INTERNAL
    Date: 02/2023

.RELASE
    11-2024
    Version 0.3 ' Added support for Default Policy and Other type of policies.

    06-2024
    Version 0.2 ' Improve output and logging.

    02/2024
    Version 0.1 ' Initial script creation with basic backup functionality.

.EXAMPLE
    # Define the Set Name
    .\EPMPoliciesBackup.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -destinationFolder "c:\EPMbackup"
    # No Set
    .\EPMPoliciesBackup.ps1 -username "user@domain" -tenant "eu" -destinationFolder "c:\EPMbackup"
    # Write output on log
    .\EPMPoliciesBackup.ps1 -username "user@domain" -tenant "eu" -destinationFolder "c:\EPMbackup"
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
    [string]$logFolder,

    [Parameter(Mandatory = $true)]
    [string]$destinationFolder
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

function Remove-InvalidCharacters {
    param (
        [string]$inputString
    )

    # Define the list of invalid characters
    $invalidCharacters = '\', '\\', '/', ':', '*', '?', '"', '<', '>', '|', '[', ']'

    # Replace each invalid character with an empty string
    foreach ($char in $invalidCharacters) {
        $inputString = $inputString -replace [regex]::Escape($char), ''
    }

    return $inputString
}

function Save-PolicyOrAppGroup {
    param (
        [string]$managerURL,
        [string]$setID,
        [string]$setName,
        [string]$objectType,  # 'Server' for policies, 'ApplicationGroups' for application groups
        [hashtable]$sessionHeader,
        [string]$folder
    )

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
        44 = "Agent Configuration"
        46 = "Remove Admin"
        47 = "Deception"
    }

    $policiesURI = "$managerURL/EPM/API/Sets/$setID/Policies/$objectType/Search?limit=1000"
    $policiesDetailsURI = "$managerURL/EPM/API/Sets/$setID/Policies/$objectType/"

    # Filter policy type: https://docs.cyberark.com/EPM/latest/en/Content/WebServices/PolicyTypes.htm#Grouppolicytypes
    $policyFilter = ""
    if ($objectType -eq "Server") {
        $policyFilter = @{
            "filter" = "PolicyGroupType IN 3,4,5,6,7,13"
        }  | ConvertTo-Json
    }

    # Filter application groups type: https://docs.cyberark.com/EPM/latest/en/Content/WebServices/ApplicationGroupTypes.htm#Groupsofapplicationgrouptypes
    else {
        $policyFilter = @{
            "filter" = "PolicyGroupType EQ 15"
       }  | ConvertTo-Json
    }

    # Get Policy List
    $policiesList = Invoke-EPMRestMethod -Uri $policiesURI -Method 'POST' -Headers $sessionHeader -Body $policyFilter

    Write-Log "Retrieved $($policiesList.FilteredCount) Policies" WARN
    $policyCounter = 1
    
    foreach ($policy in $policiesList.Policies) {

        # Destination File Name
        $policyType = $policyTypes[$policy.PolicyType]
        $policyFileName = Remove-InvalidCharacters "$($setName)_$($policyType)_$($policy.PolicyName).json"
        $policyPath = "$($folder)\$($policyFileName)"

        Write-Log "$policyCounter\$($policiesList.FilteredCount) - Processing $($policyType): $($policy.PolicyName)" INFO

<# Start incremental backup 
        # Check the policy in log hashtable
        if ($changeLog.ContainsKey($policy.PolicyId)) {
            # The key is present in the log
            if ($changeLog[$policy.PolicyId] -ne $policy.ModifiedDate) {
                # Policy was updated. Retrieve the policy details
                Write-Log "-> $($policy.PolicyName) has been modified, updating $policyPath..." INFO
                $getPolicyObj = Invoke-EPMRestMethod -Uri "$policiesDetailsURI$($policy.PolicyID)" -Method 'GET' -Headers $sessionHeader
                
                # Store policy in JSON file
                $getPolicyObj.Policy | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Force
                Write-Log "-> $($policy.PolicyName) saved to $($policyPath)" INFO
                
                # Update log Hashtable
                $changeLog[$policy.PolicyId] = $policy.ModifiedDate
            } else {
                Write-Log "-> $($policy.PolicyName) currently saved in $($policyPath) was not modified." INFO
            }
        } else {
Stop Incremental backup #> 
            # Policy never stored. Retrieve the policy details
            Write-Log "-> Requesting $($policy.PolicyName) from EPM Console" WARN
            $getPolicyObj = Invoke-EPMRestMethod -Uri "$policiesDetailsURI$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
            # Store policy in JSON file
            $getPolicyObj.Policy | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Force 
            Write-Log "-> $($policy.PolicyName) saved to $($policyPath)" INFO
<# Start incremental backup
            # Updatre log Hashtable
            $changeLog[$policy.PolicyId] = $policy.ModifiedDate
        }
Stop Incremental backup #> 
        $policyCounter++
    }
}

function Save-AdvAgentConf {
    param (
        [string]$managerURL,
        [string]$setID,
        [string]$setName,
        [hashtable]$sessionHeader,
        [string]$folder
    )

    Write-Log "Getting Advanced Agent General Configuration" WARN
    $getPolicyObj = Invoke-EPMRestMethod -Uri "$managerURL/EPM/API/Sets/$setID/Policies/AgentConfiguration/$setID" -Method 'GET' -Headers $sessionHeader

    # Destination File Name
    $policyType = $policyTypes[$getPolicyObj.Policy]
    $policyFileName = Remove-InvalidCharacters "$($setName)_$($policyType)_$($getPolicyObj.Policy.Name).json"
    $policyPath = "$($folder)\$($policyFileName)"

    # Store policy in JSON file
    $getPolicyObj | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Force
    Write-Log "$($getPolicyObj.Name) saved to $($policyPath)" INFO
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

# Sanitize FolderName, SET name could contain character not allowed 
$destinationFolder = "$destinationFolder\$($set.setName)" -replace ('\[|\]', '')

# Preparing the destination folder based on TimeStamp
$currentDate = "{0:yyMMddHHmm}" -f (Get-Date)
$destinationFolder = "$destinationFolder\$($currentDate)"
New-Item -ItemType Directory -Path $destinationFolder | Out-Null
Write-Host "Backup folder created in $destinationFolder" -ForegroundColor Yellow

<# Start incremental backup
# Log file
$logFile = "$destinationFolder\EPMPolicyBackup.log"

# Preparing the hashatable where to log details
$changeLog = @{}
if (Test-Path -Path $logFile) {
    Import-Csv -Path $logFile | ForEach-Object {
        $changeLog[$_.PolicyID] = $_.ModifiedDate
    }
}
Stop incremental backup #>

# Export Policies, App Group and Adv Config
Write-Box "Export Application Policies"
Save-PolicyOrAppGroup -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -objectType "Server" -sessionHeader $sessionHeader -folder $destinationFolder
Write-Box "Export Application Groups"
Save-PolicyOrAppGroup -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -objectType "ApplicationGroups" -sessionHeader $sessionHeader -folder $destinationFolder
Write-Box "Export Agent Configuration"
Save-AdvAgentConf -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -sessionHeader $sessionHeader -folder $destinationFolder

<# Start incremental backup
# Saving Log
$changeLog.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        PolicyID = $_.Key
        ModifiedDate = $_.Value
    }
} | Export-Csv -Path $logFile -NoTypeInformation
Stop incremental backup #>

