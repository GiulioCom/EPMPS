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
    File: EPMHealthCheckGathering.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1 - INTERNAL
    Date: 10/2024
    
.EXAMPLE
    .\EPMHealthCheckGathering.ps1 -username user@domain -tenant eu -set "Set Name" -log
    
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

    $expSeverity = $severity
    $exceedingChars = 5-$severity.Length
    
    while ($exceedingChars -ne 0) {
        $expSeverity = $expSeverity + " "
        $exceedingChars--
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$expSeverity] $message"

    switch ($severity) {
        "INFO" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Green"
            }
        }
        "WARN" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Yellow"
            }
        }
        "ERROR" {
            if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
                $ForegroundColor = "Red"
            }
        }
    }

    Write-Host $logMessage -ForegroundColor $ForegroundColor

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
        [Parameter(Mandatory)]
        [string]$InputString
    )

    # Define invalid characters for file names
    $invalidCharacters = '[\\/:*?"<>|[\]]'

    # Remove invalid characters
    $sanitizedString = $InputString -replace $invalidCharacters, ''

    return $sanitizedString
}

function Save-File {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Content,          # The content to save (can be JSON, HTML, etc.)

        [Parameter(Mandatory)]
        [string]$FileName,         # Base name for the file (extension included)

        [Parameter(Mandatory)]
        [string]$DestFolder        # Destination folder to save the file
    )

    try {
        # Ensure the destination folder exists
        if (-not (Test-Path -Path $DestFolder)) {
            New-Item -ItemType Directory -Path $DestFolder -Force | Out-Null
        }

        # Sanitize and construct the full file name
        $sanitizedFileName = Remove-InvalidCharacters -InputString $FileName
        $fullPath = Join-Path -Path $DestFolder -ChildPath $sanitizedFileName

        # Determine the file type and save accordingly
        if ($sanitizedFileName -like "*.json") {
            $Content | ConvertTo-Json -Depth 10 | Set-Content -Path $fullPath -Force
        }
        elseif ($sanitizedFileName -like "*.html") {
            $Content | Set-Content -Path $fullPath -Force -Encoding UTF8
        }
        else {
            throw "Unsupported file type: $sanitizedFileName"
        }

        Write-Log "File saved to: $fullPath" INFO
#        return $fullPath
    }
    catch {
        Write-Log "Failed to save file: $_" ERROR
        throw
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

$DefPolPropMap = @{
    "DetectUserActionsOnly" = "Detection mode (Windows only)"
    "DetectEvents4StdUsers" = "Standard end users: Detect unhandled applications when administrative privileges are required"
    "PMDetectStdNotificationMode" = "Prompt end users when an unhandled application requires administrative privileges"
    "DetectEvents4AdmUsers" = "Administrative end users: Detect unhandled applications when administrative privileges are required"
    "PMDetectAdmNotificationMode" = "Notify end users when an unhandled application requires administrative privileges"
    "DetectHeuristics" = "Detect unsuccessful application launches using heuristics (Windows only)"
    "PMDetectHeuristicsNotification" = "Prompt users when an application is elevated manually"
    "ManualRequests" = "Allow end users to submit elevation requests (Windows, macOS)"
    "PMDetectManualNotification" = "Prompt users when an application is elevated manually"
    "DetectLaunches" = "Detect launch of unhandled applications"
    "ACLaunchWinNotification" = "Notify end users when an unhandled application is launched (Windows only)"
    "DetectInstallations" = "Detect installation of unhandled applications (Windows only)"
    "DetectAccess" = "Detect access to sensitive resources by unhandled applications"
    "Apply2OldApps" = "Include applications installed before the EPM agent"
    "RestrictAccessInternet" = "Restriction - Internet"
    "RestrictAccessIntranet" = "Restriction - Intranet"
    "RestrictAccessShares" = "Restriction - Network shares"
    "RestrictAccessRAM" = "Restriction - Memory of other processes"
    "ACRestrictAccessWinNotification" = "Notify end users when an unauthorized access attempt occurs (Windows)"
    "ACRestrictAccessMacNotification" = "Notify end users when an unauthorized access attempt occurs (macOS)"
    "IntDetectLaunches" = "Detect launch of unhandled applications downloaded from the internet"
    "IntLaunchWinNotification" = "Notify end users when an unhandled application is launched"
    "IntDetectInstallations" = "Detect installation of unhandled applications downloaded from the internet"
    "IntDetectAccess" = "Detect access to the sensitive resources by unhandled applications downloaded from the internet"
    "IntRestrictAccessWinNotification" = "Notify end users when an unauthorized access attempt occurs"
    "IntSendBlockEvent" = "Detect attempts to launch unhandled applications downloaded from the internet"
    "IntBlockWinNotification" = "Notify end user when unhandled application downloaded from the internet is blocked (Windows only)"
    "Elevate4StdUsers" = "Standard end users: Elevate unhandled applications when privileges are required"
    "PMElevateWinNotification" = "Prompt users when elevation is necessary - Windows"
    "PMElevateMacNotification" = "Prompt users when elevation is necessary - macOS"
    "PMElevateLinuxNotification" = "Prompt users when elevation is necessary - Linux"
    "Elevate4AdmUsers" = "Administrative end users: Elevate unhandled applications when privileges are required"
    "ElevateManualRequests" = "Add elevation option to Windows Explorer context menu for unhandled applications"
    "PMElevateManualNotification" = "Prompt users when an application is elevated manually"
    "SendBlockEvent" = "Detect attempts to launch unhandled applications"
    "ACBlockWinNotification" = "Notify users when an unhandled application is blocked (Windows)"
    "ACBlockMacNotification" = "Notify users when an unhandled application is blocked (macOS)"
    "Apply2WindowsPrograms" = "Include controlled Windows OS programs (Windows Only)"
}
##########

### Script Functions

function Write-Log-HTML {
    param (
        [Parameter(Mandatory)]
        [object]$Text,          # The content to save (can be JSON, HTML, etc.)

        [Parameter(Mandatory)]
        [string]$ErrorLevel,    # Accroding to WriteLog function

        [int]$Column,         # The column in the table

        [string]$rowSpan         # The rowspan if needed

    ) 

    $row = ""

    if ($rowspan) {
        $row = "<td rowspan=$rowspan>$Text</td>"
        Write-Log " - $Text" -severity $ErrorLevel
    } else {
        
        $row = "<td>$Text</td>"
        switch ($column) {
            1 { 
                $row += "<td></td><td></td>"
                Write-Log " - $Text" -severity $ErrorLevel
            }
            2 { 
                $row += "<td></td>"
                Write-Log " -- $Text" -severity $ErrorLevel
            }
            3 {
                Write-Log " --- $Text" -severity $ErrorLevel
            }
            Default {}
        }
    }

    return "$row"
}

function Write-RowDefPolType-New {
    param (
        [Parameter(Mandatory)]
        [int]$param,         # The parameter name
        
        [Parameter(Mandatory)]
        [string]$HTMLtable   # The HTML table containing <tr> tags
    ) 

    # Count the number of <tr> tags in the HTML table
    $rowspan = ($HTMLtable -split "<tr>").Count

    # Construct the return value
    $returnValue = "$($policyTypes[$param]): $(Resolve-DefPolValue -value $($policyDetails.Policy.IsActive))"
    #Write-Log "$returnValue" INFO -ForegroundColor DarkMagenta

    # Return the new table row with calculated rowspan
    return "<tr><td rowspan=$rowspan>$returnValue</td></tr>$HTMLtable"
}

function Write-RowSingleData {
    param (
        [Parameter(Mandatory)]
        [string]$param,

        [string]$serverParam
    ) 
    
    # Check if $serverParam is null or an empty string
    if ([string]::IsNullOrWhiteSpace($serverParam)) {
        # Fallback to $param if $serverParam is not provided
        $serverParam = $param
    }

    $returnValue = "$($DefPolPropMap[$param]): $(Resolve-DefPolValue -value $($policyDetails.Policy.$serverParam))"
    #Write-Log "- $returnValue" INFO
    return "<tr><td>$returnValue</td><td></td></tr>"
}
function Get-PolicyTarget {
    
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

    $returnTarget = ""
    $includeComp = ""
    $includeCompADGroup = ""
    $IncludeUsers = ""
    $excludeComp = ""
    $excludeCompADGroup = ""

    if ($policyDetails.Policy.IsAppliedToAllComputers -eq $false) {
        if ($policy.Executors.Count -gt 0) {
            $policyDetails.Policy.Executors | ForEach-Object {
                if ($_.IsIncluded -eq $true) {
                    $includeComp += "<div>$($ExecutorType[($_.ExecutorType)]): $($_.Name)</div>"
                } else {
                    $excludeComp += "<div>$($ExecutorType[($_.ExecutorType)]): $($_.Name)</div>"
                }
            }
        } else {
            $includeComp = "All"
            $excludeComp = "None"
        }

        if ($policy.Accounts.Count -gt 0) {
            $policy.Accounts | ForEach-Object {
                $IncludeUsers += "<div>$($AccountType[($_.AccountType)]): $($_.SamName)</div>"
            }
        } else {
            $IncludeUsers = "All"
        }

        if ($policy.IncludeADComputerGroups.Count -gt 0) {
            $policy.Accounts | ForEach-Object {
                $includeCompADGroup += "$($AccountType[($_.AccountType)]): $($_.SamName)"
            }
        } else {
            $includeCompADGroup = "All"
        }

        if ($policy.ExcludeADComputerGroups.Count -gt 0) {
            $policy.Accounts | ForEach-Object {
                $excludeCompADGroup += "$($AccountType[($_.AccountType)]): $($_.SamName)"
            }
        } else {
            $excludeCompADGroup = "All"
        }
    } else {
        $includeComp = "All"
        $includeCompADGroup = "All"
        $IncludeUsers = "All"
        $excludeComp = "None"
        $excludeCompADGroup = "None"
    }

    $returnTarget +="<tr><td colspan=2>Apply Policy to</td></tr>"
    $returnTarget +="<tr><td>&nbsp;&nbsp;Computers in this set</td><td>$includeComp</td></tr>"
    $returnTarget +="<tr><td>&nbsp;&nbsp;Computers in AD security groups</td><td>$includeCompADGroup</td></tr>"
    $returnTarget +="<tr><td>&nbsp;&nbsp;Users and groups</td><td>$IncludeUsers</td></tr>"
    $returnTarget +="<tr><td colspan=2>Exclude from policy</td></tr>"
    $returnTarget +="<tr><td>&nbsp;&nbsp;Computers in this set</td><td>$excludeComp</td></tr>"
    $returnTarget +="<tr><td>&nbsp;&nbsp;Computers in AD security groups</td><td>$excludeCompADGroup</td></tr>"

    return $returnTarget
}

function Resolve-DefPolValue {
    param (
        $name,
        [Parameter(Mandatory)]
        $value
    )

    $PMDetectNotification = @{
        0 = "Suppress OS Native Notification"
        1 = "Allow OS Notification"
        2 = "Use EPM Notification"
    }

    $resolvedValue = ""

    if ($name) {
        # In case the Name is one to be resolved
        switch ($name) {
            "PMDetectStdNotificationMode" { $resolvedValue = $PMDetectNotification[$value] }
            "DetectUserActionsOnly" {
                if ($value -eq $true) {
                    $resolvedValue = "Manually launched applications only (default)"
                } else {
                    $resolvedValue = "Automatically and manually launched applications"
                }
            }
        #      Default { $DisplayValue = $optionValue }
        }
    } else {
        switch ($value) {
            $true      { $resolvedValue = "ON" }
            $false     { $resolvedValue = "OFF" }
        }
    }

    return $resolvedValue
}

function Get-AdvancedParameters {
    param (
        [PSCustomObject]$paramObject    # The object to inspect
    )

    # Initialize a variable to accumulate the string
    $output = ""

    foreach ($param in $paramObject.PSObject.Properties){
        if ($param.Value -is [PSCustomObject]) {
            $output += "$($param.Name):["
            $output += Get-AdvancedParameters -paramObject $param.Value
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

    function Resolve-Advanced {
        param (
            [Parameter(Mandatory)]
            $paramName,
            $paramValue
        )
    
        $outputAdv = ""
        if ($paramName -eq "IsActive") {
            $outputAdv = if ($paramValue) { "ON" } else { "OFF" }
        } else {
            $outputAdv = Resolve-DisplayName -OriginalName $paramName
            if ($null -ne $paramValue) {
                $outputAdv += ": $(Resolve-Value -optionName $paramName -optionValue $paramValue)"
            }
        }
    
        return $outputAdv
    }

    # Initialize a variable to accumulate the string
    $output = @()

    foreach ($param in $paramObject.PSObject.Properties){
        if ($param.Value -is [PSCustomObject]) {
            $output += "<li>$(Resolve-Advanced -paramName $param.Name)"
            $output += Get-AdvancedParametersHTML -paramObject $param.Value
            $output += "</li>"
        } elseif ($param.Value -is [Array]) {
            $output += "<li>$(Resolve-Advanced -paramName $param.Name):</li>"
            $output += "<ul>"
            $output += ($param.Value | ForEach-Object { "<li>$($_)</li>" }) -join "`n"
            $output += "</ul>"
        } else {
            $output += "<li>$(Resolve-Advanced -paramName $param.Name -paramValue $param.Value)</li>`n"
        }
    } 
    
    # Combine the output into a single string
    return "<ul>$($output -join "`n")</ul>"
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

function Write-RowAdvAgentType {
    param (
        [Parameter(Mandatory)]
        [string]$param,         # The parameter name
        
        [Parameter(Mandatory)]
        [string]$HTMLtable   # The HTML table containing <tr> tags
    ) 

    # Count the number of <tr> tags in the HTML table
    $rowspan = ($HTMLtable -split "<tr>").Count

    # Return the new table row with calculated rowspan
    return "<tr><td rowspan=$rowspan>$param</td></tr>$HTMLtable"
}

function Resolve-Value {
    param (
        [Parameter(Mandatory)]
        $optionName,
        [Parameter(Mandatory)]
        $optionValue
    )

    $ProtectAdministrativeUserGroupsMap = @{
        0 = "Off"
        1 = "Elevate"
        2 = "All"
    }
    
    $ConfirmElevationElevationTypeMap = @{
        0 = "Custom"
        1 = "Administrators"
    }
    
    $IsNetworkSharesFullSupportMap = @{
        0 = "Limited"
        1 = "Full"
    }

    $ElevationTypeMap = @{
        0 = "Custom"
        1 = "Administrators"
    }

    $DisplayValue = $optionValue

    # In case the the value is a Boolen    
    switch ($optionValue) {
        ""         { $DisplayValue = "No Value" }
        $true      { $DisplayValue = "ON" }
        $false     { $DisplayValue = "OFF" }
    #    default    { $setting = $agentParam.Value.Value }
    }
    
    
    # In case the Name is one to be resolved
    switch ($optionName) {
        "ElevationType" { $DisplayValue = $ElevationTypeMap[$optionValue] }
        "ProtectAdministrativeUserGroups" { $DisplayValue = $ProtectAdministrativeUserGroupsMap[$optionValue] }
        "ConfirmElevationElevationType" { $DisplayValue = $ConfirmElevationElevationTypeMap[$optionValue] }
        "IsNetworkSharesFullSupport" { $DisplayValue = $IsNetworkSharesFullSupportMap[$optionValue] }
  #      Default { $DisplayValue = $optionValue }
    }
    
    return $DisplayValue
}

function Resolve-DisplayName {
    param (
        [Parameter(Mandatory)]
        [string]$OriginalName   # The original name to resolve
    )

    $displayNameMap = @{
        "ExtendedProtection" = "Extended Protection"
        "AgentSelfDefense" = "Agent self-defense"
        "SupportInfoFilePassword" = "Support info file password"
        "ProtectAdministrativeUserGroups" = "Protect administrative user groups"
        "AntiTamperingProtection" = "Anti-tampering protection"
        "ProtectElevatedProcessesFromDllHijacking" = "Protect elevated processes from DLL hijacking"
        "DataCollection" = "Data collection"
        "CollectPolicyAuditData" = "Collect policy audit data"
        "ExcludeNewFilesFromTheApplicationCatalogAndInbox" = "Exclude new files from the Application Catalog and Events Management"
        "FileTypesToScanForApplicationCatalog" = "File types to scan for Application Catalog"
        "EventQueueFlushPeriod" = "Event queue flush period"
        "PolicyAuditEventFlushPeriod" = "Policy audit event flush period"
        "ThreatProtectionEventQueueFlushInterval" = "Threat protection event queue flush period"
        "CollectEventsInEventLog" = "Collect events in event log"
        "CollectEventsInWmi" = "Collect events in WMI"
        "CollectTemporaryFiles" = "Collect temporary files"
        "CollectEventsTriggeredByServiceAccounts" = "Collect events triggered by service accounts"
        "CollectChildCommandEvent" = "Collect child command events"
        "ReportUserGroupsInEvents" = "Report user groups in events"
        "CollectProtectedAccounts" = "Collect protected accounts"
        "Policies" = "Policies"
        "EnablePolicySuspension" = "Enable policy suspension"
        "ConfirmElevation" = "Confirm elevation"
        "ThreatProtectionExcludedApplications" = "Threat protection excluded applications"
        "HeartbeatTimeout" = "Heartbeat timeout"
        "PolicyConditionTimeout" = "Policy condition timeout"
        "ScriptTimeout" = "Script timeout"
        "PolicyUpdateInterval" = "Policy update interval"
        "RefreshWindowsDesktopPolicyUpdate" = "Refresh Windows desktop after policy update"
        "PolicyUsageInAgentTrace" = "Trace policy usage on agents"
        "WellKnownPublishers" = "Well known publishers"
        "ExcludeServiceAccountsFromAccessRestrictions" = "Exclude service accounts from access restrictions"
        "ElevateSccmForUserInstallations" = "Elevate SCCM ""for user"" installations"
        "RestrictCmdSpecialCharacters" = "Restrict CMD special characters" 
        "AllowedInterpreters" = "Allowed interpreters"
        "LinuxDefaultEnvVariables" = "Environment variables"
        "AgentBehavior" = "Agent behavior"
        "ExcludeFilesFromProtectionWindows" = "Exclude files from policies (Windows)"
        "ExcludeFilesFromProtectionMacos" = "Exclude files from policies (macOS)"
        "MonitorSystemProcesses "= "Monitor system processes"
        "StoreFileInfoInExtendedAttributes" = "Store file info in extended attributes"
        "EnableDllSupport" = "Enable DLL support"
        "VerifyDigitalSignatureOnScripts" = "Verify digital signature on scripts"
        "DiscoverSourceUrl" = "Discover source URL"
        "DiscoverSourceEmail" = "Discover source email"
        "IsNetworkSharesFullSupport" = "Support network shares"
        "BootStartDriver" = "Boot-start driver"
        "MonitorSipFiles" = "Monitor SIP files"
        "AllowRootDelegationForRootPrograms" = "Allow root permission for root programs"
        "SudoGraceValidationPeriod" = "Sudo grace validation period"
        "ProhibitSudoersFileModification" = "Prevent sudoers file modification"
        "TraceNewFiles" = "Trace new files"
        "SudoNoPassword" = "Sudo no password"
        "SudoSecurePath" = "Sudo secure path"
        "AllowedPreloaders" = "Allowed preloader"
        "SudoersAllowsUserSpecificationOverriding" = "Allow sudoers interoperability"
        "EndpointUi" = "Endpoint UI"
        "ShowIconInTaskMenuBar" = "Show icon in task/menu bar"
        "ShowTabInFileProperties" = "Show CyberArk EPM tab in File Properties"
        "ShowControlPanelOnDesktop" = "Show CyberArk EPM Control Panel on desktop"
        "HideWindowsRunAsMenuItems" = "Hide Windows ""Run As..."" menu items"
        "HideAgentFromInstalledPrograms" = "Hide CyberArk EPM agent from installed programs"
        "ShellElevateMenuText" = "Shell elevate menu text"
        "EnableTabbedBrowsing" = "Enable tabbed browsing"
        "StepUpAuthentication" = "IdP settings"
        "CyberArkIdentity" = "CyberArk Identity "
        "CustomIdentityProvider" = "Custom identity provider"
        "CloudEnvironments" = "Cloud environments"
        "EnableAzureActiveDirectory" = "Enable Azure Active Directory"
        "OfflinePolicyAuthorizationGenerator" = "Offline policy authorization generator"
    #= "Enable Offline Policy Authorization Generator" INFO
    #= "Enable 'Run with Authorization token'" INFO
        "VideoRecording" = "Audit video configuration"
        "AllowRun" = "Allow application to run if recording is unavailable"
        "MaxMovieLengthMinutes" = "Maximum movie length"
        "VideoAuditRetentionDays" = "Video file retention period"
        "MovieLocation" = "Video file destination"
        # FileTypesToScanForApplicationCatalog
        "ExecutableExtensions" = "Windows - Executable extensions"
        "InstallationPackageExtensions" = "Windows - Installation package extensions"
        "DLLExtensions" = "Windows - Dynamic link library (DLL) extensions"
        "ScriptFileExtensions" = "Windows - Script file extensions"
        "MacInstallationExtensions" = "macOS - Executables"
        "MacAllExecutableFiles" = "macOS - Installation"
        # CollectProtectedAccounts
        "ProtectedAccountsIntervalHours" = "Protected accounts interval (Number of hours between accounts collection)"
        # EnablePolicySuspension - ConfirmElevation"
        "UserGroup" = "Target users and/or groups"
        "accountType" = "Account Type"
    }

    # Attempt to resolve the display name from the map
    $displayName = $DisplayNameMap[$OriginalName]

    # Fallback to the original name if no mapping is found
    if (-not $displayName) {
        $displayName = $OriginalName
    }

    return $displayName
} 

function Create-HTMLReport {
    param (
        [string]$ReportTitle = "",
        [string]$SubTitle = "",
        [string]$SetName = "",
        [string]$TableHeader = "",
        [string]$TableBody = ""
    )

    # HTML structure
    $htmlContent = @"
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>$ReportTitle - $SetName</title>
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
                h2, h3 {
                    text-align: center;
                    color: #666;
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
                    background-color: rgb(20, 133, 179);
                    color: white;
                    font-weight: 600;
                }
                tr {
                    background-color: rgb(167, 201, 225);
                }
                /* Even row color: rgb(199, 221, 236) */
                //tr:nth-child(even) {
                //    background-color: rgb(199, 221, 236);
                //}
                /* Odd row color: rgb(167, 201, 225) */
                //tr:nth-child(odd) {
                //    background-color: rgb(167, 201, 225);
                //}
                /* Add hover effect for rows */
                //tr:hover {
                //    background-color: #f1f1f1;
                //}
            </style>
        </head>
        <body>
            <h1>$ReportTitle</h1>
            <h2>$SubTitle</h2>
            <h3>$SetName</h3>
            <table>
                <tr>$($TableHeader -join "`n")</tr>
                $TableBody
            </table>
        </body>
    </html>
"@

    return $htmlContent
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

Write-Box "$scriptName"

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

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue


# Get Default policy
Write-Log "Collecting Default Policy..." INFO -ForegroundColor Blue

$policiesSearchFilter = @{
    "filter" = "policyGroupType EQ 7"
} | ConvertTo-Json

$policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter

# Save policy file
Save-File -Content $policySearch -FileName "$($set.setName)_DefaultPolicies.json" -DestFolder "$PSScriptRoot\\EPM_HC_Report"

# Analyze Policy result
Write-Log "Processing Default Policy..." INFO -ForegroundColor Magenta

$defaultPolicyTableBody = ""

foreach ($policy in $policySearch.Policies) {
    if ($policy.isActive -eq $true) {
        $policyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.policyId)" -Method 'GET' -Headers $sessionHeader
        switch ($policy.PolicyType) {
            # [PM Detect]
            1 { 
                $PMDetectTable = ""

                $PMDetectTable += Write-RowSingleData -param "DetectUserActionsOnly"
            
                $DetectEvents4StdUsers = "$($DefPolPropMap["DetectEvents4StdUsers"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectEvents4StdUsers))"
                #Write-Log "-- $DetectEvents4StdUsers" INFO
                if ($policyDetails.Policy.DetectEvents4StdUsers) {
                    $PMDetectStdNotificationMode = "$($DefPolPropMap["PMDetectStdNotificationMode"]): $(Resolve-DefPolValue -name "PMDetectStdNotificationMode" -value $($policyDetails.Policy.PMDetectStdNotificationMode))"
                #    Write-Log "--- $DetectEvents4StdUsers" INFO
                }
                $PMDetectTable += "<tr><td>$DetectEvents4StdUsers</td><td>$PMDetectStdNotificationMode</td></tr>"

                $DetectEvents4AdmUsers = "$($DefPolPropMap["DetectEvents4AdmUsers"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectEvents4AdmUsers))"
                #Write-Log "-- $DetectEvents4AdmUsers" INFO
                if ($policyDetails.Policy.DetectEvents4AdmUsers) {
                    $PMDetectAdmNotificationMode = "$($DefPolPropMap["PMDetectAdmNotificationMode"]): $(Resolve-DefPolValue -name "PMDetectAdmNotificationMode" -value $($policyDetails.Policy.PMDetectStdNotificationMode))"
                #    Write-Log "--- $DetectEvents4StdUsers" INFO
                }
                $PMDetectTable += "<tr><td>$DetectEvents4AdmUsers</td><td>$PMDetectAdmNotificationMode</td></tr>"
                
                $DetectHeuristics = "$($DefPolPropMap["DetectHeuristics"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectHeuristics))"
                #Write-Log "-- $DetectHeuristics" INFO
                if ($policyDetails.Policy.DetectHeuristics -and $policyDetails.Policy.PMDetectStdNotificationMode.Id -ne "00000000-0000-0000-0000-000000000000") {
                    $PMDetectHeuristicsNotification = "$($DefPolPropMap["PMDetectHeuristicsNotification"]): Baloon or Dialog"
                #    Write-Log "--- $PMDetectHeuristicsNotification" INFO
                }
                $PMDetectTable += "<tr><td>$DetectHeuristics</td><td>$PMDetectHeuristicsNotification</td></tr>"

                $ManualRequests = "$($DefPolPropMap["ManualRequests"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.ManualRequests))"
                #Write-Log "-- $ManualRequests" INFO
                if ($policyDetails.Policy.ManualRequests -and $policyDetails.Policy.PMDetectManualNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                    $PMDetectManualNotification = "$($DefPolPropMap["PMDetectManualNotification"]): Baloon or Dialog"
                #    Write-Log "--- $PMDetectManualNotification" INFO
                }
                $PMDetectTable += "<tr><td>$ManualRequests</td><td>$PMDetectManualNotification</td></tr>"
               
                $PMDetectTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $PMDetectTable

            }
            # [AC Detect]
            2 {
                $ACDetectTable = ""
                
                $DetectLaunches = "$($DefPolPropMap["DetectLaunches"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectLaunches))"
                #Write-Log "- $DetectLaunches" INFO
                if ($policyDetails.Policy.DetectLaunches -and $policyDetails.Policy.ACLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                    $ACLaunchWinNotification = "$($DefPolPropMap["ACLaunchWinNotification"]): Baloon or Dialog"
                #    Write-Log "-- $ACLaunchWinNotification" INFO
                }
                $ACDetectTable += "<tr><td>$DetectLaunches</td><td>$ACLaunchWinNotification</td></tr>"

                $ACDetectTable += Write-RowSingleData -param "DetectInstallations"

                $ACDetectTable += Write-RowSingleData -param "DetectAccess"
                
                $ACDetectTable += Write-RowSingleData -param "Apply2OldApps"

                $ACDetectTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $ACDetectTable
            }
            # [AC Restrict]
            3 {
                $ACRestrictTable = ""
                
                $DetectLaunches = "$($DefPolPropMap["DetectLaunches"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectLaunches))"
                #Write-Log "- $DetectLaunches" INFO
                if ($policyDetails.Policy.DetectLaunches -and $policyDetails.Policy.ACLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                    $ACLaunchWinNotification = "$($DefPolPropMap["ACLaunchWinNotification"]): Baloon or Dialog"
                #    Write-Log "-- $ACLaunchWinNotification" INFO
                }
                $ACRestrictTable += "<tr><td>$DetectLaunches</td><td>$ACLaunchWinNotification</td></tr>"

                $ACRestrictTable += Write-RowSingleData -param "DetectInstallations"

                $RestrictAccessInternet = "$($DefPolPropMap["RestrictAccessInternet"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessInternet))"
                #Write-Log "- $RestrictAccessInternet" INFO

                $RestrictAccessIntranet = "$($DefPolPropMap["RestrictAccessIntranet"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessIntranet))"
                #Write-Log "- $RestrictAccessIntranet" INFO

                $RestrictAccessShares = "$($DefPolPropMap["RestrictAccessShares"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessShares))"
                #Write-Log "- $RestrictAccessShares" INFO

                $RestrictAccessRAM = "$($DefPolPropMap["RestrictAccessRAM"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessRAM))"
                #Write-Log "- $RestrictAccessRAM" INFO

                if ($policyDetails.Policy.ACRestrictAccessWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    $ACRestrictAccessWinNotification = "Dialog or Baloon"
                } else {
                    $ACRestrictAccessWinNotification = "OFF"
                }

                if ($policyDetails.Policy.ACRestrictAccessMacNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    $ACRestrictAccessMacNotification = "Dialog"
                } else {
                    $ACRestrictAccessMacNotification = "OFF"
                }

                #Write-Log "-- $($DefPolPropMap["ACRestrictAccessWinNotification"]): $ACRestrictAccessWinNotification" INFO
                #Write-Log "-- $($DefPolPropMap["ACRestrictAccessMacNotification"]): $ACRestrictAccessMacNotification" INFO

                $ACRestrictTable += "<tr><td>$RestrictAccessInternet</td><td rowspan=2>$($DefPolPropMap["ACRestrictAccessWinNotification"]): $ACRestrictAccessWinNotification</td></tr>"
                $ACRestrictTable += "<tr><td>$RestrictAccessIntranet</td></tr>"
                $ACRestrictTable += "<tr><td>$RestrictAccessShares</td><td rowspan=2>$($DefPolPropMap["ACRestrictAccessMacNotification"]): $ACRestrictAccessMacNotification</td></tr>"
                $ACRestrictTable += "<tr><td>$RestrictAccessRAM</td></tr>"

                $ACRestrictTable += Write-RowSingleData -param "Apply2OldApps"

                $ACRestrictTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $ACRestrictTable
            }
            # [RP Detect] and [RP Restrict]
            {$_ -eq 4 -or $_ -eq 5} {
                $RPDetectTable = ""
                
                $RestrictRulesPathList = ""
                foreach ($RestrictRulesPath in $policyDetails.Policy.RPRestrictRulesPaths) {
                    $pattern = ""
                    if ($RestrictRulesPath.IsFile) {
                        $pattern = "Filename"
                    } else {
                        $pattern = "Location"
                    }
                    $RestrictRulesPathList += "<div>$($pattern): $($RestrictRulesPath.Path)</div>"
                }
                $RPDetectTable += "<tr><td>$RestrictRulesPathList</td><td></td></tr>"

                $RPDetectTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $RPDetectTable
            }
            # [Internet Detect]
            6 {
                $InternetDetectTable = ""

                $IntDetectLaunches = "$($DefPolPropMap["IntDetectLaunches"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectLaunches))"
                #Write-Log "- $IntDetectLaunches" INFO
                if ($policyDetails.Policy.DetectLaunches) {
                    if ($policyDetails.Policy.IntLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $IntLaunchWinNotification = "$($DefPolPropMap["IntLaunchWinNotification"]): Baloon or Dialog"
                    } else {
                        $IntLaunchWinNotification = "$($DefPolPropMap["IntLaunchWinNotification"]): OFF"
                    }
                }
                #Write-Log "-- $IntLaunchWinNotification" INFO
                
                $InternetDetectTable += "<tr><td>$IntDetectLaunches</td><td>$IntLaunchWinNotification</td></tr>"

                $InternetDetectTable += Write-RowSingleData -param "IntDetectInstallations" -serverParam "DetectInstallations"
                $InternetDetectTable += Write-RowSingleData -param "IntDetectAccess" -serverParam "DetectAccess"

                $InternetDetectTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $InternetDetectTable
            }             
            # [Internet Restrict]
            7 {
                $InternetRestrictTable = ""

                $IntDetectLaunches = "$($DefPolPropMap["IntDetectLaunches"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.DetectLaunches))"
                #Write-Log "- $IntDetectLaunches" INFO
                
                if ($policyDetails.Policy.DetectLaunches) {
                    if ($policyDetails.Policy.IntLaunchWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $IntLaunchWinNotification = "$($DefPolPropMap["IntLaunchWinNotification"]): Baloon or Dialog"
                    } else {
                        $IntLaunchWinNotification = "$($DefPolPropMap["IntLaunchWinNotification"]): OFF"
                    }
                }
                #Write-Log "-- $IntLaunchWinNotification" INFO

                $InternetRestrictTable += "<tr><td>$IntDetectLaunches</td><td>$IntLaunchWinNotification</td></tr>"

                $InternetRestrictTable += Write-RowSingleData -param "IntDetectInstallations" -serverParam "DetectInstallations"

                $IntRestrictAccessInternet = "$($DefPolPropMap["RestrictAccessInternet"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessInternet))"
               # Write-Log "-- $IntRestrictAccessInternet" INFO

                $IntRestrictAccessIntranet = "$($DefPolPropMap["RestrictAccessIntranet"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessIntranet))"
               # Write-Log "-- $IntRestrictAccessIntranet" INFO

                $IntRestrictAccessShares = "$($DefPolPropMap["RestrictAccessShares"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessShares))"
               # Write-Log "-- $IntRestrictAccessShares" INFO

                $IntRestrictAccessRAM = "$($DefPolPropMap["RestrictAccessRAM"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.RestrictAccessRAM))"
                #Write-Log "-- $IntRestrictAccessRAM" INFO

                if ($policyDetails.Policy.IntRestrictAccessWinNotification.Id -ne "00000000-0000-0000-0000-000000000000"){
                    $IntRestrictAccessWinNotification = "Dialog or Baloon"
                } else {
                    $IntRestrictAccessWinNotification = "OFF"
                }

              #  Write-Log "--- $($DefPolPropMap["IntRestrictAccessWinNotification"]): $IntRestrictAccessWinNotification" INFO

                $InternetRestrictTable += "<tr><td>$IntRestrictAccessInternet</td><td rowspan=4>$($DefPolPropMap["IntRestrictAccessWinNotification"]): $IntRestrictAccessWinNotification</td></tr>"
                $InternetRestrictTable += "<tr><td>$IntRestrictAccessIntranet</td></tr>"
                $InternetRestrictTable += "<tr><td>$IntRestrictAccessShares</td></tr>"
                $InternetRestrictTable += "<tr><td>$IntRestrictAccessRAM</td></tr>"

                $InternetRestrictTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $InternetRestrictTable
            }
            # [Internet Block]
            8 {
                $InternetBlockTable = ""
                
                $IntSendBlockEvent = "$($DefPolPropMap["IntSendBlockEvent"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.SendBlockEvent))"
                #Write-Log "- $IntSendBlockEvent" INFO
                if ($policyDetails.Policy.SendBlockEvent) {
                    if ($policyDetails.Policy.IntBlockWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $IntBlockWinNotification = "$($DefPolPropMap["IntBlockWinNotification"]): Baloon or Dialog"
                    } else {
                        $IntBlockWinNotification = "$($DefPolPropMap["IntBlockWinNotification"]): OFF"
                    }
                }
                #Write-Log "-- $IntBlockWinNotification" INFO

                $InternetBlockTable += "<tr><td>$IntSendBlockEvent</td><td>$IntBlockWinNotification</td></tr>"

                $InternetBlockTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $InternetBlockTable
            }
            # [PM Elevate]
            9 { 
                $PMElevateTable = ""

                $Elevate4StdUsers = "$($DefPolPropMap["Elevate4StdUsers"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.Elevate4StdUsers))"
                #Write-Log "- $Elevate4StdUsers" INFO
                if ($policyDetails.Policy.Elevate4StdUsers) {
                    if ($policyDetails.Policy.PMElevateStdWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateStdWinNotification = "$($DefPolPropMap["PMElevateWinNotification"]): Baloon or Dialog"
                    } else {
                        $PMElevateStdWinNotification = "$($DefPolPropMap["PMElevateWinNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateStdWinNotification" INFO

                    if ($policyDetails.Policy.PMElevateStdMacNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateStdMacNotification = "$($DefPolPropMap["PMElevateMacNotification"]): Dialog"
                    } else {
                        $PMElevateStdMacNotification = "$($DefPolPropMap["PMElevateMacNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateStdMacNotification" INFO

                    if ($policyDetails.Policy.PMElevateStdLinuxNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateStdLinuxNotification = "$($DefPolPropMap["PMElevateLinuxNotification"]): Dialog"
                    } else {
                        $PMElevateStdLinuxNotification = "$($DefPolPropMap["PMElevateLinuxNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateStdLinuxNotification" INFO
                }
                $PMElevateTable += "<tr><td>$Elevate4StdUsers</td><td>$PMElevateStdWinNotification<br>$PMElevateStdMacNotification<br>$PMElevateStdLinuxNotification</tr>"

                $Elevate4AdmUsers = "$($DefPolPropMap["Elevate4AdmUsers"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.Elevate4AdmUsers))"
                #Write-Log "- $Elevate4AdmUsers" INFO
                if ($policyDetails.Policy.Elevate4AdmUsers) {
                    if ($policyDetails.Policy.PMElevateAdmWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateAdmWinNotification = "$($DefPolPropMap["PMElevateWinNotification"]): Baloon or Dialog"
                    } else {
                        $PMElevateAdmWinNotification = "$($DefPolPropMap["PMElevateWinNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateAdmWinNotification" INFO

                    if ($policyDetails.Policy.PMElevateStdMacNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateAdmMacNotification = "$($DefPolPropMap["PMElevateMacNotification"]): Dialog"
                    } else {
                        $PMElevateAdmMacNotification = "$($DefPolPropMap["PMElevateMacNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateAdmMacNotification" INFO

                    if ($policyDetails.Policy.PMElevateAdmLinuxNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $PMElevateAdmLinuxNotification = "$($DefPolPropMap["PMElevateLinuxNotification"]): Dialog"
                    } else {
                        $PMElevateAdmLinuxNotification = "$($DefPolPropMap["PMElevateLinuxNotification"]): OFF"
                    }
                #    Write-Log "-- $PMElevateAdmLinuxNotification" INFO
                }
                $PMElevateTable += "<tr><td>$Elevate4AdmUsers</td><td>$PMElevateAdmWinNotification<br>$PMElevateAdmMacNotification<br>$PMElevateAdmLinuxNotification</tr>"

                $ManualRequests = "$($DefPolPropMap["ElevateManualRequests"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.ManualRequests))"
                #Write-Log "- $ManualRequests" INFO
                if ($policyDetails.Policy.ManualRequests -and $policyDetails.Policy.PMElevateManualNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                    $PMElevateManualNotification = "$($DefPolPropMap["PMDetectManualNotification"]): Baloon or Dialog"
                } else {
                    $PMElevateManualNotification = "$($DefPolPropMap["PMDetectManualNotification"]): OFF"
                }
                #Write-Log "-- $PMElevateManualNotification" INFO

                $PMElevateTable += "<tr><td>$ManualRequests</td><td>$PMElevateManualNotification</td></tr>"
               
                $PMElevateTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $PMElevateTable
            }
            # [AC Block]
            10 {
                $ACBlockTable = ""
                
                $SendBlockEvent = "$($DefPolPropMap["SendBlockEvent"]): $(Resolve-DefPolValue -value $($policyDetails.Policy.SendBlockEvent))"
                #Write-Log "- $SendBlockEvent" INFO
                if ($policyDetails.Policy.SendBlockEvent) {
                    if ($policyDetails.Policy.BlockWinNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $ACBlockWinNotification = "$($DefPolPropMap["ACBlockWinNotification"]): Baloon or Dialog"
                    } else {
                        $ACBlockWinNotification = "$($DefPolPropMap["ACBlockWinNotification"]): NO"
                    }
                #    Write-Log "-- $ACBlockWinNotification" INFO

                    if ($policyDetails.Policy.ACBlockMacNotification.Id -ne "00000000-0000-0000-0000-000000000000") {
                        $ACBlockMacNotification = "$($DefPolPropMap["ACBlockMacNotification"]): Baloon or Dialog"
                    } else {
                        $ACBlockMacNotification = "$($DefPolPropMap["ACBlockMacNotification"]): NO"
                    }
                #    Write-Log "-- $ACBlockMacNotification" INFO
                }

                $ACBlockTable += "<tr><td>$SendBlockEvent</td><td>$ACBlockWinNotification<br>$ACBlockMacNotification</td></tr>"

                $ACBlockTable += Write-RowSingleData -param "Apply2OldApps"
                $ACBlockTable += Write-RowSingleData -param "Apply2WindowsPrograms"

                $ACBlockTable += Get-PolicyTarget -policy $policyDetails.Policy

                $defaultPolicyTableBody += Write-RowDefPolType-New -param $($policyDetails.Policy.PolicyType) -HTMLtable $ACBlockTable
            }
            Default {}
        }

        #$policyDetails | ConvertTo-Json
    }
}

# Generate the HTML report
$defaultPolicyReport = Create-HTMLReport -ReportTitle "Default Policy" `
    -SubTitle "" `
    -SetName "SET: $($set.setName)" `
    -TableHeader "<th>Policy Type</th>", "<th>Main Settings</th>", "<th>Extended Settings</th>"`
    -TableBody $defaultPolicyTableBody

# Save to file
Write-Log "Store Default Policy Report..." INFO
Save-File -Content $defaultPolicyReport -FileName "$($set.setName)_DefaultPolicy.html" -DestFolder "$PSScriptRoot\\EPM_HC_Report"

# Get Agent Configuration

Write-Log "Collecting Advanced Agent General Configuration..." INFO -ForegroundColor Blue
$agentConfGeneral = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration/$($set.setId)" -Method 'GET' -Headers $sessionHeader
Save-File -Content $agentConfGeneral -FileName "$($set.setName)_AgentConf.json" -DestFolder "$PSScriptRoot\\EPM_HC_Report"

$confAgentTableBody = ""

# List of options to extract, the result may contains other data not useful
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

# Process Agent Configuration
Write-Log "Processing Advanced Agent General Configuration..." INFO -ForegroundColor Magenta

foreach ($agentParamType in $agentConfGeneral.Policy.PSObject.Properties) {
    
    if ($validOptions -contains $agentParamType.Name) {
        #Write-Log " + $($agentParamType.Name)" INFO
        
        #$prevParamTypeName = ""
        $paramTypeTable = ""
        
        foreach ($agentParam in $agentParamType.Value.PSObject.Properties){
            # Reset the variables
            #$setting = ""
            $settingHTML = ""
            $paramHTML = ""
            
            # Define the OS
            $OS = $($supportedOS[$($agentParam.Value.SupportedOS)])

            if ($agentParam.Name -eq "SupportInfoFilePasswordDefault") {
                continue # Skip this value
            }

            if ($agentParam.Value.Value -is [PSCustomObject]) {
                # If the Value is a custom object
                if ($agentParam.Name -eq "ThreatProtectionExcludedApplications" -or
                    $agentParam.Name -eq "ExcludeNewFilesFromTheApplicationCatalogAndInbox" -or
                    $agentParam.Name -eq "ExcludeFilesFromProtectionMacos" -or
                    $agentParam.Name -eq "ExcludeFilesFromProtectionWindows") {
                    if ($null -eq $agentParam.Value.Value.Applications -or $agentParam.Value.Value.Applications.Count -eq 0) {
                        # Array is empty
                        #$setting = "No Value"
                        $settingHTML = "No Value"
                    } else {
                        # Process Array 
                        #$setting = ($agentParam.Value.Value.Applications | ForEach-Object { $_.displayName }) -join ", "
                        $settingHTML = "<ul>" + ($agentParam.Value.Value.Applications | ForEach-Object { "<li>$($_.displayName)</li>" }) -join "`n" + "</ul>"
                    }
                    
                } elseif ($agentParam.Name -eq "FileTypesToScanForApplicationCatalog" ) {
                    foreach ($property in $agentParam.Value.Value.PSObject.Properties) {
                        $returnFileType = Get-FileTypesToScanForApplicationCatalog -ParamName $property.Name -ParamValue $property.Value
                    
                        #$setting += "$($property.Name): $returnFileType - "
                        $paramHTML += "<li>$(Resolve-DisplayName -OriginalName $property.Name): $returnFileType</li>`n"
                    }
                    $settingHTML = "<ul>$paramHTML</ul>"
                } else {
                    #$setting = Get-AdvancedParameters -paramObject $agentParam.Value.Value
                    $settingHTML = Get-AdvancedParametersHTML -paramObject $agentParam.Value.Value
                }

            } elseif ($agentParam.Value.Value -is [array]) {
                # If the Value is an array
                if ($null -eq $agentParam.Value.Value -or $agentParam.Value.Value.Count -eq 0) {
                    # Array is empty
                    #$setting = "No Value"
                    $settingHTML = "No Value"
                } else {
                    # Array has data, join elements with a comma
                    #$setting = $agentParam.Value.Value -join ", "
                    $paramHTML = "<ul>" + ($agentParam.Value.Value | ForEach-Object { "<li>$_</li>" }) -join "`n" + "</ul>"
                    $settingHTML = $paramHTML
                }
                
            } else {
                # If the value are  BOOL, INT, String or others
                #$setting = Resolve-Value -optionName $agentParam.Name -optionValue $agentParam.Value.Value
                $settingHTML = Resolve-Value -optionName $agentParam.Name -optionValue $agentParam.Value.Value
            }

            $paramName = Resolve-DisplayName -OriginalName $agentParam.Name
            $paramTypeTable += "<tr><td>$paramName</td><td>$OS</td><td>$settingHTML</td></tr>"
          
            #Write-Log " + - $($agentParam.Name) - $OS - $setting" INFO
          #  $htmlContent += "<tr><td>$paramTypeName</td><td>$paramName</td><td>$OS</td><td>$settingHTML</td></tr>"
            #$confAgentTableBody += "<tr><td>$paramTypeName</td><td>$paramName</td><td>$OS</td><td>$settingHTML</td></tr>"
        }

        $paramTypeName = Resolve-DisplayName -OriginalName $agentParamType.Name

        $confAgentTableBody += Write-RowAdvAgentType -param $paramTypeName -HTMLtable $paramTypeTable
        #$paramTypeTable = ""

#        $prevParamTypeName = $paramTypeName
    }
}

$agentConfReport = Create-HTMLReport -ReportTitle "Agent Configuration" `
    -SubTitle "Configuration Policy: $($agentConfGeneral.Policy.Name)" `
    -SetName "SET: $($set.setName)" `
    -TableHeader "<th>ParameterType</th>", "<th>Parameter</th>", "<th>OS</th>", "<th>Settings</th>"`
    -TableBody $confAgentTableBody

# Save to file
Write-Log "Store Agent Configuration Report..." INFO
Save-File -Content $agentConfReport -FileName "$($set.setName)_AgentConf.html" -DestFolder "$PSScriptRoot\\EPM_HC_Report"
