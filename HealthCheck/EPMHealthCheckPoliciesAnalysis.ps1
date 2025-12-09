<#
.SYNOPSIS
    Policy export file analysis EPM
    Users \ Groups - Working
    Application details - Not yet started

.DESCRIPTION

.PARAMETER EPMPoliciesExport
    EPM File exported from EPM

.PARAMETER exportCSVPath
    The name of the EPM set.

.PARAMETER tenant
    Export output in CSV file

.PARAMETER destinationFolder


.NOTES
    File: EPMPolicyAnalysisHC.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 09/2025
    Last Modified: 09/2025
#>

param (

    [Parameter(Mandatory, HelpMessage = "EPM File exported from EPM")]
    [string]$EPMPoliciesExport,

    [Parameter(Mandatory, HelpMessage = "Export output in CSV file")]
    [string]$exportCSVPath
)

## Write-Host Wrapper and log management
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

    # Set default colors if not provided in the function
    if (-not $PSBoundParameters.ContainsKey("ForegroundColor")) {
        switch ($severity) {
            "INFO" { $ForegroundColor = "Green" }
            "WARN" { $ForegroundColor = "Yellow" }
            "ERROR" { $ForegroundColor = "Red" }
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
    
    # Create the top and bottom lines
    $line = "-" * $title.Length

    # Print the box
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
    Write-Log "| $title |" -severity INFO -ForegroundColor Cyan
    Write-Log "+ $line +" -severity INFO -ForegroundColor Cyan
}

function Evaluate-Patterns {
    param (
        [object]$Application,
        [string]$PatternName,
        [int]$Priority
    )

    $result = [PSCustomObject]@{
        PatternName = $PatternName
        Weight = 0
        value = ""
    }

    $compareAsMapping = @{
        0 = "exact"
        1 = "prefix"
        2 = "contains"
        3 = "wildcards"
        4 = "regExp"
    }

    # Manage use case
    if (!$Application.patterns.$PatternName.isEmpty) {
        
        $result.Weight = $Priority
        $result.value = $Application.patterns.$PatternName.content

        # Manage exceptions

        # Reduce weight if the compareAs is not EXACTLY
        # But before, check compareAs is available (for example the property LOCATION doesn't have it)
        if ($null -ne $Application.patterns.$PatternName -and $null -ne $Application.patterns.$PatternName.compareAs) {
            if ($Application.patterns.$PatternName.compareAs -ne 0) {
                $result.Weight = $result.Weight / 2
            }
        }
        
        # Publisher: Reduce weight if the publisher is not SPECIFIC
        if ($PatternName -eq "PUBLISHER") {
            if ($Application.patterns.PUBLISHER.signatureLevel -ne 2) {
                $result.Weight = $result.Weight / 2
            }
        }
        # Location: Reduce the weight if subfolders are enabled
        if ($PatternName -eq "LOCATION") {
            if ($Application.patterns.LOCATION.withSubfolders -eq $true) {
                $result.Weight = $result.Weight / 2
            }
        }
        # Owner: Get the correct value
        if ($PatternName -eq "OWNER") {
            foreach ($account in $Application.patterns.$PatternName.accounts){
                $result.value += "$($account.name) "
            }
        }
    }

    return $result
}

function Process-Application{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [object]$Application,
        [string]$PolicyType,
        [string]$Action
    )

    $AppTypeMapping = @{
        2 = "Group"             # Patterns: None
        3 = "EXE"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, File description, Company name, Original file name, File version, Product version, File origin (Source), Parent, Service name (must be empty)
        4 = "Script"            # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, File origin (Source), Parent
        5 = "MSI"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, Company name, Product code, Upgrade code, Product version, File origin (Source), Parent
        6 = "MSU"               # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, File origin (Source), Parent
        7 = "WebApp"            # Patterns: URL
        8 = "WinAdminTask"      # Patterns: Admin task ID
        9 = "ActiveX"           # Patterns: File name, Publisher, Code URL, Mime type, CLSID, Version
        13 = "FileSystemNode"   # Patterns: File name or Location
        14 = "Registry Key"     # Patterns: Registry key
        15 = "COM"              # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, CLSID
        17 = "WinService"       # Patterns: Service name
        18 = "USB Device"       # Patterns: Vendor Id, Vendor Name, Product Id, Product Name, Instance Id
        19 = "Optical Disc2"    # Patterns: Instance Id
        20 = "WinApp"           # Patterns: Publisher, App package name, App package version, Capabilities
        21 = "DLL"              # Patterns: File name, Arguments, Location, Location Type, Owner, Publisher, Product name, File description, Company name, Original file name, File version, Product version, File origin (Source), Parent
        22 = "macPKG"           # Patterns: File name, Location, Publisher, Mac DMG image
        23 = "MacSysPref"       # Patterns: Admin task ID
        24 = "MacApplication"   # Patterns: File name, Location, Publisher, Bundle ID, Bundle version
        26 = "MacDMG"           # Patterns: File name, Location, Publisher
        28 = "Linux command"    # Patterns: File name, Arguments, Location, Linux link name, Linux script interpreter, Linux run as user
        104 = "MacSUDO"         # Patterns: File name, Arguments, Publisher
    }
   
    # Define the priority weight
    $priority1 = 30
    $priority2 = 20
    $priority3 = 10

    # Set the threshold, the value can change based on policy type or policy action
    $threshold = 0
    
    # Policy type Linux or MacOS 60, Windows = 90
    if ($PolicyType -eq 12 -or $PolicyType -eq 13) {
        $threshold = 60
    } else {
        $threshold = 90
    }
    
    # Policy action allow or deny
    if ($action -eq 2 -or $action -eq 1) {
        $threshold = 30
    }
    
    $unspportedAppType = $false    

    $matchedConditions = @()
    $totalWeight = 0

    $appTypeName = $AppTypeMapping[$Application.applicationType]

    # Evaluate Patterns based on application type, 
    switch ($appTypeName) {
        'EXE' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "FILE_DESCRIPTION" $priority2
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "ORIGINAL_FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'Script' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'MSI' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'MSU' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'ActiveX' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "CLSID" $priority3
        }
        'COM' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "CLSID" $priority3
        }
        'WinApp' {
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'DLL' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PRODUCT_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "FILE_DESCRIPTION" $priority2
            $matchedConditions += Evaluate-Patterns $Application "COMPANY_NAME" $priority2
            $matchedConditions += Evaluate-Patterns $Application "ORIGINAL_FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
        }
        'macPKG' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacApplication' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacDMG' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'MacSUDO' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
        }
        'Linux command' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LINUX_LINK_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "LINUX_SCRIPT_INTERPRETER" $priority2
        }
        default {
            # Default action if none of the conditions match
            Write-Log "Application Type '$appTypeName' not supported." WARN
            $unspportedAppType = $true
        }
    }

    if (!$unspportedAppType) {
        # Evaluate common pattern, such as HASH
        switch ($appTypeName) {
            { ($_ -eq "EXE") -or ($_ -eq "Script") -or ($_ -eq "MSI") -or ($_ -eq "MSU") -or ($_ -eq "COM") -or ($_ -eq "DLL") -or 
              ($_ -eq "Linux command") -or ($_ -eq "macPKG") -or ($_ -eq "MacApplication") -or ($_ -eq "MacDMG") -or ($_ -eq "MacSUDO")} {
                if ($Application.patterns.FILE_NAME.hash) {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "HASH"
                        Weight = "90"
                        value = $Application.patterns.FILE_NAME.hash
                    }
                }
            }
        }
    
        # Calculate Total value
        $totalWeight = ($matchedConditions | Measure-Object -Property Weight -Sum).Sum
  
        # Evaluate global pattern, such as child process
        switch ($appTypeName) {
            { ($_ -eq "EXE") -or ($_ -eq "Script") -or ($_ -eq "DLL") } {
            # If child process is enabled divide the total
                if ($Application.childProcess -eq $true) {
                    $totalWeight = $totalWeight / 2
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "WIN_CHILD_PROCESS"
                        Weight = -$totalWeight
                        value = "Enabled"
                    } 
                } else {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "WIN_CHILD_PROCESS"
                        Weight = -0
                        value = "Disabled"
                    }
                }                
            }
            'Linux command' {
                # Linux  Child Process   
                $linuxChildProcessMapping = @{
                    0 = "Deny"
                    1 = "Allow"
                    2 = "Allow and Restrict"
                }

                switch ($Application.LinuxChildProcess) {
                    0 { $totalWeight = $totalWeight }
                    1 { $totalWeight = $totalWeight / 2 }
                    2 { $totalWeight = $totalWeight / 2 }
                }
                $linuxChildProcessName = $linuxChildProcessMapping[$Application.LinuxChildProcess]
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "LIN_CHILD_PROCESS"
                    Weight = -$totalWeight
                    value = "$linuxChildProcessName"
                }
            
                # Linux Sudo no password
                if ($Application.linuxSudoNoPassword -eq $true) {
                    $totalWeight = $totalWeight / 2
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "LIN_SUDO_NO_PASSWORD"
                        Weight = -$totalWeight / 2
                        value = "Enabled"
                    }
                } else {
                    $matchedConditions += [PSCustomObject]@{
                        PatternName = "LIN_SUDO_NO_PASSWORD"
                        Weight = -0
                        value = "Disabled"
                    }
                }
            }
        }
        
        # Define the application name for better output
        $applicationName = $null

        # Define the priority order for pattern names
        $priorityPatterns = @("FILE_NAME", "ORIGINAL_FILE_NAME", "PUBLISHER")

        foreach ($pattern in $priorityPatterns) {
            $matchingCondition = $matchedConditions | Where-Object { $_.PatternName -eq $pattern }

            if ($matchingCondition) {
                $applicationName = $Application.patterns.$($pattern).content
                break
            }
        }
       
        if (-not $applicationName) {
            # If none of the conditions matched, assign $Application.id
            $applicationName = $Application.id
        }      
        
<#
        If ($totalWeight -ge $threshold) {
            if (!$notCompliant) {
                Write-Log "> $applicationName - $totalWeight - Compliant to Policy Standards" -severity INFO -ForegroundColor Green
                Write-Log "|-> Application Type: $appTypeName" -severity INFO -ForegroundColor Gray
                Write-Log "|-> Application Description: $($Application.description)" -severity INFO -ForegroundColor Gray
                # Iterate through each $matchedConditions
                foreach ($condition in $matchedConditions) {
                    # Print PatternName when weight is greater than 0
                    if ($condition.Weight -ne 0) {
                        Write-Log "|-> $($condition.PatternName): $($condition.value) = $($condition.Weight)" -severity INFO -ForegroundColor Gray
                    }
                }
            }
        } else {
            Write-Log "> $applicationName - $totalWeight - Not Compliant to Policy Standards" -severity WARN -ForegroundColor Yellow
            Write-Log "|-> Application Type: $appTypeName" -severity WARN -ForegroundColor Gray
            Write-Log "|-> Application Description: $($Application.description)" -severity WARN -ForegroundColor Gray
            # Iterate through $matchedConditions
            foreach ($condition in $matchedConditions) {
                # Print PatternName if Weight is greater than 0
                if ($condition.Weight -ne 0) {
                    Write-Log "|-> $($condition.PatternName): $($condition.value) = $($condition.Weight)" -severity WARN -ForegroundColor Gray
                }
            }
        }
#>
    }

    if ($pause) {
        Write-Host "Press Enter to continue..."
        $null = Read-Host
    }

    return [PSCustomObject]@{
        ApplicationName         = $applicationName
        ApplicationType         = $appTypeName
        TotalWeight             = $totalWeight
        ApplicationDefinition   = $matchedConditions
    }
}

## Mapping EPM Data
$actionMap = @{
    1 = "Allow"
    2 = "Block"
    3 = "Elevate"        
    4 = "Elevate if necessary"
    5 = "CollectUAC"
    6 = "ElevateRequest"
    9 = "ExecSript"
    10 = "AgentConfiguration"
    11 = "SetSecurityPermissions"
    13 = "DefineUpdater"
    17 = "Loosely connected devices"
    18 = "DefineDeveloperTool"
    20 = "AdHocElevate"
}

$policyTypeMap = @{
    1 =	"Privilege Management Detect"
    2 =	"Application Control Detect"
    3 =	"Application Control Restrict"
    4 =	"Ransomware Protection Detect"
    5 =	"Ransomware Protection Restrict"
    6 =	"INT Detect"
    7 =	"INT Restrict"
    8 =	"INT Block"
    9 =	"Privilege Management Elevate"
    10 = "Application Control Block"
    11 = "Advanced Windows"
    12 = "Advanced Linux"
    13 = "Advanced Mac"
    17 = "Recommended Block Windows OS Applications"
    18 = "Predefined App Groups Win"
    20 = "Developer Applications"
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
    36 = "User Policy - Set Security Permissions for File System and Registry Keys"
    37 = "User Policy - Set Security Permissions for Services"
    38 = "User Policy - Set Security Permissions for Removable Storage (USB, Optical Discs)"
    39 = "Collect UAC actions by Local Admin"
    40 = "JIT Access and Elevation"
    41 = "Deploy Script"
    42 = "Execute Script"
    45 = "Agent Configuration"
    46 = "Remove Admin"
    47 = "Deception"
}

$accountTypeMap = @{
    0 = "Group"
    1 = "Single"
    2 = "Manually entered"
    4 = "Azure user"
    5 = "Azure group"
    6 = "AD user"
    7 = "AD group"
    8 = "IdP user"
    9 = "IdP group"
    10 = "Entra ID computer"
}

$executorTypeMap = @{
    0 = "Computer Group"
    1 = "Single Computer"
}
###

function Get-PolicyTargets {
    param (
        [object]$policy
    )
    
    $targetsRows = @()
    
    $targetsData = [PSCustomObject]@{
        PolicyName                      = $policy.Name
        PolicyType                      = $policyTypeMap[$policy.PolicyType]
        PolicyAction                    = $actionMap[$policy.Action]
        AppliedToAll                    = $policy.IsAppliedToAllComputers
        IncludeExecutor                 = $null
        ExcludeExecutor                 = $null
        ExecutorType                    = $null
        IncludeUsersGroupsSid           = $null
        IncludeUsersGroupsAccountType   = $null
        IncludeUsersGroupsDisplayName   = $null
        IncludeUsersGroupsSamName       = $null
    }

    # Process Executors if they exist
    if ($policy.Executors.Count -gt 0 ){
        Write-Log "Processing Executors..." INFO
        foreach ($executor in $policy.Executors) {
            
            $executorData = $TargetsData.PSObject.Copy()
            
            $executorData.ExecutorType = $executorTypeMap[$executor.ExecutorType]
            if ($executor.IsIncluded) {
                $executorData.IncludeExecutor = $executor.Name
            } else {
                $executorData.ExcludeExecutor = $executor.Name
            }
            $targetsRows += $executorData
        }
    }

    # Check the Accounts
    if ($policy.Accounts.Count -gt 0 ){
        Write-Log "Processing Accounts..." INFO
        foreach ($account in $policy.Accounts) {
            $accountData = $TargetsData.PSObject.Copy()

            $accountData.IncludeUsersGroupsSid = $account.Sid
            $accountData.IncludeUsersGroupsAccountType = $accountTypeMap[$account.AccountType]
            $accountData.IncludeUsersGroupsDisplayName = $account.DisplayName
            $accountData.IncludeUsersGroupsSamName = $account.SamName
                        
            $targetsRows += $accountData
        }
    }

    if ($targetsRows.Count -eq 0) {
        $targetsRows += $TargetsData
    }

    return $targetsRows
}

function Get-ApplicationData {
    param (
        [object]$policy
    )

    $applicationsRows = @()
    
    $baseApplicationData = [PSCustomObject]@{
        PolicyName                  = $policy.Name
        PolicyType                  = $policyTypeMap[$policy.PolicyType]
        PolicyAction                = $actionMap[$policy.Action]
        ApplicationName             = $null
        ApplicationType             = $null
        TotalWeight                 = $null
        FILE_NAME                   = $null
        ARGUMENTS                   = $null
        LOCATION                    = $null
        LOCATION_TYPE               = $null
        OWNER                       = $null
        PUBLISHER                   = $null
        PRODUCT_NAME                = $null
        FILE_DESCRIPTION            = $null
        COMPANY_NAME                = $null
        ORIGINAL_FILE_NAME          = $null
        PARENT_PROCESS              = $null
        CLSID                       = $null
        LINUX_LINK_NAME             = $null
        LINUX_SCRIPT_INTERPRETER    = $null
        HASH                        = $null
        WIN_CHILD_PROCESS           = $null
        LIN_CHILD_PROCESS           = $null
        LIN_SUDO_NO_PASSWORD        = $null
    }

    Write-Log "Processing Applications..." INFO

    foreach ($application in $policy.Applications) {
        $applicationData = $baseApplicationData.PSObject.Copy()
        $result = Process-Application -Application $application -PolicyType $($policy.PolicyType) -action $($policy.Action)
        
        $applicationData.ApplicationName = $result.ApplicationName
        $applicationData.ApplicationType = $result.ApplicationType
        $applicationData.TotalWeight     = $result.totalWeight

        foreach ($definition in $result.ApplicationDefinition){
            $applicationData.($definition.PatternName) = $definition.value
        }
        
        $applicationsRows += $applicationData
    }

    if ($applicationsRows.Count -eq 0) {
        $applicationsRows += $baseApplicationData
    }

    return $applicationsRows
}

function Get-PolicyProperties {
    param (
        [object]$policy
    )
    
    $properties = [PSCustomObject]@{
        name                            = $policy.Name
        Description                     = $policy.Description
        Type                            = $policyTypeMap[$policy.PolicyType]
        Action                          = $actionMap[$policy.Action]
        Audit                           = $policy.Audit
        IsActive                        = $policy.IsActive
        Priority                        = $policy.Priority
    }
    return $properties
}

function appCounter {
    param (
        [object]$policyFile
    )

    function Get-AppGroupCounter {
        param (
            [string]$appGroupName
        )

        foreach ($application in $appGroupCounter) {
            if ($application.Name -eq $appGroupName) {
                return $application.Count
            }
        }
    }
    

    <#    
    $appCount = [PSCustomObject]@{
        Name  = $policy.Name
        Type  = $policy.Description
        Count = $policyTypeMap[$policy.PolicyType]
    }
    #>

    $appGroupCounter = @()
    $policyCounter = @()
    
    #extract application
    foreach ($appGroups in $policyFile.AppGroups) {
        $applicationCounter = [PSCustomObject]@{
            Name = $appGroups.Name
            Type = $appGroups.PolicyType
            Count = $appGroups.Applications.Count
        }
        $appGroupCounter += $applicationCounter
    }

    foreach ($policy in $policyFile.Policies) {
        $totalApp = 0
        #$appGroups = @()
        $appGroups = @{}
        foreach ($application in $policy.Applications) {
            if ($application.applicationType -eq 2) {
                $appGroupCount = Get-AppGroupCounter $($application.displayName)
                $appGroups[$application.displayName] = $appGroupCount
                $totalApp += $appGroupCount
            } else { $totalApp++ }
        }
        
        $applicationCounter = [PSCustomObject]@{
            Name = $policy.Name
            Type = $policy.PolicyType
            AppGroups = $appGroups
            Count = $totalApp
        }
        $policyCounter += $applicationCounter
    }

    foreach ($policy in $policyCounter) {
        Write-Log "$($policy.Name) - Total Application defined = $($policy.Count)" INFO
        if ($policy.AppGroups.Count -ne 0) {
            Write-Log "Defined App Groups:" INFO
            foreach ($appGroup in $policy.AppGroups.GetEnumerator()) {
                Write-Log "  $($appGroup.Name) - $($appGroup.Value)" INFO
            }
        }
    }

    # 
}

### Begin Script ###

Write-Box "$scriptName"

if (-not (Test-Path $EPMPoliciesExport)){
    Write-Log "Unable access EPM policies export file '$EPMPolicyExport'" ERROR
    exit 1
} else {
    $EPMPoliciesContent = Get-Content -Path $EPMPoliciesExport -Raw -Encoding UTF8
    $EPMPolicies = $EPMPoliciesContent | ConvertFrom-Json
}


$policiesTarget = @()
$policiesApplication = @()
$policiesProperties = @()

$fileCSVPoliciesTarget = Join-Path $exportCSVPath "PoliciesTarget.csv"
$fileCSVPoliciesApplications = Join-Path $exportCSVPath "PoliciesApplications.csv"
$fileCSVpoliciesProperties = Join-Path $exportCSVPath "PoliciesProperties.csv"

$totalPolicy = $EPMPolicies.Policies.Count
$countPolicy = 1

foreach ($policy in $EPMPolicies.Policies) {
    Write-Log "Processing $countPolicy / $totalPolicy - $($policy.Name)" INFO
    $policiesTarget += Get-PolicyTargets $policy
    $policiesApplication += Get-ApplicationData $policy
    $policiesProperties += Get-PolicyProperties $policy
    $countPolicy++
}

if ($policiesTarget.Count -gt 0) {
    $policiesTarget | Export-Csv -Path $fileCSVPoliciesTarget -NoTypeInformation -Force -Encoding UTF8
    Write-Log "Storing Target data in $fileCSVpoliciesTarget..." INFO
} else {
    Write-Log "No Policies Target found to export to CSV." WARN
}

if ($policiesApplication.Count -gt 0) {
    $policiesApplication | Export-Csv -Path $fileCSVPoliciesApplications -NoTypeInformation -Force -Encoding UTF8
    Write-Log "Storing Target data in $fileCSVPoliciesApplications..." INFO
} else {
    Write-Log "No Policies Applications found to export to CSV." WARN
}

if ($policiesProperties.Count -gt 0) {
    $policiesProperties | Export-Csv -Path $fileCSVpoliciesProperties -NoTypeInformation -Force -Encoding UTF8
    Write-Log "Storing Target data in $fileCSVpoliciesProperties..." INFO
} else {
    Write-Log "No Policies Target found to export to CSV." WARN
}


appCounter $EPMPolicies

