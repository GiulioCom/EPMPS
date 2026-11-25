<#
.SYNOPSIS
    Policy export file analysis EPM
    Users \ Groups - OK
    Application details - OK

.DESCRIPTION

.PARAMETER EPMPoliciesExport
    EPM File exported from EPM

.PARAMETER exportCSVPath
    The name of the EPM set.

.PARAMETER tenant
    Export output in CSV file

.PARAMETER destinationFolder


.NOTES
    File: Test-IdiraEpmPolicyHealth.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.2
    Created: 09/2025

    Update: 11/2026
    - Add gathering Application Group application definition
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory, HelpMessage = "EPM Policies export")]
    [ValidateScript({
        if (Test-Path -LiteralPath $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$EpmPoliciesExport,

    [Parameter(Mandatory, HelpMessage = "Export output in CSV file")]
    [string]$ExportCsvPath
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

$EpmPatternMatrix = @{
    'EXE'            = @(
        @{ Name = 'FILE_NAME';          Priority = 30 }
        @{ Name = 'ARGUMENTS';          Priority = 30 }
        @{ Name = 'LOCATION';           Priority = 30 }
        @{ Name = 'LOCATION_TYPE';      Priority = 20 }
        @{ Name = 'OWNER';              Priority = 10 }
        @{ Name = 'PUBLISHER';          Priority = 30 }
        @{ Name = 'PRODUCT_NAME';       Priority = 10 }
        @{ Name = 'FILE_DESCRIPTION';   Priority = 20 }
        @{ Name = 'COMPANY_NAME';       Priority = 20 }
        @{ Name = 'ORIGINAL_FILE_NAME'; Priority = 30 }
        @{ Name = 'PARENT_PROCESS';     Priority = 10 }
    )
    'Script'         = @(
        @{ Name = 'FILE_NAME';      Priority = 30 }
        @{ Name = 'ARGUMENTS';      Priority = 30 }
        @{ Name = 'LOCATION';       Priority = 30 }
        @{ Name = 'LOCATION_TYPE';  Priority = 20 }
        @{ Name = 'OWNER';          Priority = 10 }
        @{ Name = 'PUBLISHER';      Priority = 30 }
        @{ Name = 'PARENT_PROCESS'; Priority = 10 }
    )
    'MSI'            = @(
        @{ Name = 'FILE_NAME';      Priority = 30 }
        @{ Name = 'ARGUMENTS';      Priority = 30 }
        @{ Name = 'LOCATION';       Priority = 30 }
        @{ Name = 'LOCATION_TYPE';  Priority = 20 }
        @{ Name = 'OWNER';          Priority = 10 }
        @{ Name = 'PUBLISHER';      Priority = 30 }
        @{ Name = 'PRODUCT_NAME';   Priority = 10 }
        @{ Name = 'COMPANY_NAME';   Priority = 20 }
        @{ Name = 'PARENT_PROCESS'; Priority = 10 }
    )
    'ActiveX'        = @(
        @{ Name = 'FILE_NAME'; Priority = 30 }
        @{ Name = 'PUBLISHER'; Priority = 30 }
        @{ Name = 'CLSID';     Priority = 10 }
    )
    'COM'            = @(
        @{ Name = 'FILE_NAME';     Priority = 30 }
        @{ Name = 'ARGUMENTS';     Priority = 30 }
        @{ Name = 'LOCATION';      Priority = 30 }
        @{ Name = 'LOCATION_TYPE'; Priority = 20 }
        @{ Name = 'OWNER';         Priority = 10 }
        @{ Name = 'PUBLISHER';     Priority = 30 }
        @{ Name = 'CLSID';         Priority = 10 }
    )
    'WinApp'         = @(
        @{ Name = 'PUBLISHER'; Priority = 30 }
    )
    'MacBundle'      = @(
        @{ Name = 'FILE_NAME'; Priority = 30 }
        @{ Name = 'LOCATION';  Priority = 30 }
        @{ Name = 'PUBLISHER'; Priority = 30 }
    )
    'MacSUDO'        = @(
        @{ Name = 'FILE_NAME'; Priority = 30 }
        @{ Name = 'ARGUMENTS'; Priority = 30 }
        @{ Name = 'PUBLISHER'; Priority = 30 }
    )
    'Linux command'  = @(
        @{ Name = 'FILE_NAME';                Priority = 30 }
        @{ Name = 'LOCATION';                 Priority = 30 }
        @{ Name = 'ARGUMENTS';                Priority = 30 }
        @{ Name = 'LINUX_LINK_NAME';          Priority = 10 }
        @{ Name = 'LINUX_SCRIPT_INTERPRETER'; Priority = 20 }
    )
}

# Identical rule arrays
$EpmPatternMatrix['DLL']            = $EpmPatternMatrix['EXE']
$EpmPatternMatrix['MSU']            = $EpmPatternMatrix['Script']
$EpmPatternMatrix['macPKG']         = $EpmPatternMatrix['MacBundle']
$EpmPatternMatrix['MacApplication'] = $EpmPatternMatrix['MacBundle']
$EpmPatternMatrix['MacDMG']         = $EpmPatternMatrix['MacBundle']

$EpmHashSupportedTypes = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('EXE', 'Script', 'MSI', 'MSU', 'COM', 'DLL', 'Linux command', 'macPKG', 'MacApplication', 'MacDMG', 'MacSUDO'),
    [System.StringComparer]::OrdinalIgnoreCase
)

$LinuxChildProcessMap = @{
    0 = 'Deny';
    1 = 'Allow';
    2 = 'Allow and Restrict'
}
###

function Measure-EpmApplicationPattern {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Application,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PatternName,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority
    )

    $weight = 0.0
    $value  = ''

    # Resolve the target pattern node once (StrictMode-safe) to avoid repeated dynamic lookups
    $pattern = $null
    if ($null -ne $Application.PSObject.Properties['patterns'] -and $null -ne $Application.patterns) {
        $patternProp = $Application.patterns.PSObject.Properties[$PatternName]
        if ($null -ne $patternProp) { $pattern = $patternProp.Value }
    }

    $isEmptyProp = if ($null -ne $pattern) { $pattern.PSObject.Properties['isEmpty'] }

    if ($null -ne $pattern -and $null -ne $isEmptyProp -and -not $isEmptyProp.Value) {
        $weight = [double]$Priority
        $value  = [string]$pattern.content

        # Halve weight if compareAs exists and is not Exact (0)
        $compareAsProp = $pattern.PSObject.Properties['compareAs']
        if ($null -ne $compareAsProp -and $null -ne $compareAsProp.Value -and $compareAsProp.Value -ne 0) {
            $weight /= 2
        }

        # Mutually exclusive evaluation for pattern-specific modifiers
        switch ($PatternName) {
            'PUBLISHER' {
                $sigProp = $pattern.PSObject.Properties['signatureLevel']
                if ($null -ne $sigProp -and $sigProp.Value -ne 2) {
                    $weight /= 2
                }
            }
            'LOCATION' {
                $subProp = $pattern.PSObject.Properties['withSubfolders']
                if ($null -ne $subProp -and $subProp.Value -eq $true) {
                    $weight /= 2
                }
            }
            'OWNER' {
                $accountsProp = $pattern.PSObject.Properties['accounts']
                if ($null -ne $accountsProp -and $null -ne $accountsProp.Value) {
                    $names = foreach ($account in $accountsProp.Value) {
                        if (-not [string]::IsNullOrWhiteSpace($account.name)) { $account.name }
                    }
                    $joinedNames = $names -join ' '
                    $value = (@($value, $joinedNames) | Where-Object { $_ -ne '' }) -join ' '
                }
            }
        }
    }

    # Construct output object once with consistent PascalCase properties
    [pscustomobject]@{
        PatternName = $PatternName
        Weight      = $weight
        Value       = $value
    }
}

function Measure-EpmApplication {
    <#
    .SYNOPSIS
        Evaluates all security patterns and risk modifiers for a single EPM application definition.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Application,

        [Parameter()]
        [switch]$Pause
    )

    try {
        $appTypeName       = $script:AppTypeMapping[$Application.applicationType]
        $matchedConditions = [System.Collections.Generic.List[object]]::new()
        $totalWeight       = 0.0
        $applicationName   = $null

        if ([string]::IsNullOrEmpty($appTypeName) -or -not $script:EpmPatternMatrix.ContainsKey($appTypeName)) {
            Write-Log "Application Type '$($Application.applicationType)' ($appTypeName) not supported." WARN
        }
        else {
            # 1. Evaluate all pattern rules for this application type in a single pass
            foreach ($rule in $script:EpmPatternMatrix[$appTypeName]) {
                $condition = Measure-EpmApplicationPattern -Application $Application -PatternName $rule.Name -Priority $rule.Priority
                $matchedConditions.Add($condition)
                $totalWeight += $condition.Weight
            }

            # 2. Evaluate file hash (StrictMode-safe property check + numeric weight)
            if ($script:EpmHashSupportedTypes.Contains($appTypeName) -and
                $null -ne $Application.PSObject.Properties['patterns'] -and
                $null -ne $Application.patterns -and
                $null -ne $Application.patterns.PSObject.Properties['FILE_NAME'] -and
                $null -ne $Application.patterns.FILE_NAME -and
                $null -ne $Application.patterns.FILE_NAME.PSObject.Properties['hash'] -and
                -not [string]::IsNullOrEmpty($Application.patterns.FILE_NAME.hash)) {

                $matchedConditions.Add([pscustomobject]@{
                    PatternName = 'HASH'
                    Weight      = 90.0
                    Value       = $Application.patterns.FILE_NAME.hash
                })
                $totalWeight += 90.0
            }

            # 3. Apply global risk modifiers (accurate penalty tracking)
            switch ($appTypeName) {
                { $_ -in 'EXE', 'Script', 'DLL' } {
                    $cpProp = $Application.PSObject.Properties['childProcess']
                    if ($null -ne $cpProp -and $cpProp.Value -eq $true) {
                        $penalty = $totalWeight / 2
                        $totalWeight -= $penalty
                        $matchedConditions.Add([pscustomobject]@{
                            PatternName = 'WIN_CHILD_PROCESS'
                            Weight      = -$penalty
                            Value       = 'Enabled'
                        })
                    } else {
                        $matchedConditions.Add([pscustomobject]@{
                            PatternName = 'WIN_CHILD_PROCESS'
                            Weight      = 0.0
                            Value       = 'Disabled'
                        })
                    }
                }
                'Linux command' {
                    $lcpProp  = $Application.PSObject.Properties['LinuxChildProcess']
                    $lcpCode  = if ($null -ne $lcpProp -and $null -ne $lcpProp.Value) { [int]$lcpProp.Value } else { 0 }
                    $lcpLabel = if ($script:LinuxChildProcessMap.ContainsKey($lcpCode)) { $script:LinuxChildProcessMap[$lcpCode] } else { "Unknown ($lcpCode)" }

                    $lcpPenalty = 0.0
                    if ($lcpCode -in 1, 2) {
                        $lcpPenalty = $totalWeight / 2
                        $totalWeight -= $lcpPenalty
                    }
                    $matchedConditions.Add([pscustomobject]@{
                        PatternName = 'LIN_CHILD_PROCESS'
                        Weight      = -$lcpPenalty
                        Value       = $lcpLabel
                    })

                    $sudoProp = $Application.PSObject.Properties['linuxSudoNoPassword']
                    if ($null -ne $sudoProp -and $sudoProp.Value -eq $true) {
                        $sudoPenalty = $totalWeight / 2
                        $totalWeight -= $sudoPenalty
                        $matchedConditions.Add([pscustomobject]@{
                            PatternName = 'LIN_SUDO_NO_PASSWORD'
                            Weight      = -$sudoPenalty
                            Value       = 'Enabled'
                        })
                    } else {
                        $matchedConditions.Add([pscustomobject]@{
                            PatternName = 'LIN_SUDO_NO_PASSWORD'
                            Weight      = 0.0
                            Value       = 'Disabled'
                        })
                    }
                }
            }

            # 4. Resolve display name from the first non-empty priority pattern (no pipeline overhead)
            foreach ($priorityName in 'FILE_NAME', 'ORIGINAL_FILE_NAME', 'PUBLISHER') {
                foreach ($cond in $matchedConditions) {
                    if ($cond.PatternName -eq $priorityName -and -not [string]::IsNullOrWhiteSpace($cond.Value)) {
                        $applicationName = $cond.Value
                        break
                    }
                }
                if ($null -ne $applicationName) { break }
            }
        }

        if ([string]::IsNullOrWhiteSpace($applicationName)) {
            $idProp = $Application.PSObject.Properties['id']
            $applicationName = if ($null -ne $idProp -and -not [string]::IsNullOrWhiteSpace($idProp.Value)) { $idProp.Value } else { 'Unknown' }
        }

        if ($Pause) {
            $null = Read-Host -Prompt 'Press Enter to continue'
        }

        [pscustomobject]@{
            ApplicationName       = $applicationName
            ApplicationType       = $appTypeName
            TotalWeight           = $totalWeight
            ApplicationDefinition = $matchedConditions
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-EpmApplicationData {
    <#
    .SYNOPSIS
        Evaluates all application definitions in an EPM policy or Application Group and returns CSV-ready rows.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy
    )

    try {
        $applicationsRows = [System.Collections.Generic.List[object]]::new()

        $policyName = $Policy.Name
        $policyType = $script:policyTypeMap[$Policy.PolicyType]

        # Action is absent on Application Group entries; explicit $null check preserves enum value 0 on policies
        $policyAction = ''
        $actionProp   = $Policy.PSObject.Properties['Action']
        if ($null -ne $actionProp -and $null -ne $actionProp.Value) {
            $policyAction = $script:actionMap[$actionProp.Value]
        }

        # Stamp a fixed-schema ordered dictionary per row so Export-Csv columns stay identical and ordered
        $newRowTemplate = {
            [ordered]@{
                PolicyName               = $policyName
                PolicyType               = $policyType
                PolicyAction             = $policyAction
                ApplicationName          = $null
                ApplicationType          = $null
                TotalWeight              = $null
                FILE_NAME                = $null
                ARGUMENTS                = $null
                LOCATION                 = $null
                LOCATION_TYPE            = $null
                OWNER                    = $null
                PUBLISHER                = $null
                PRODUCT_NAME             = $null
                FILE_DESCRIPTION         = $null
                COMPANY_NAME             = $null
                ORIGINAL_FILE_NAME       = $null
                PARENT_PROCESS           = $null
                CLSID                    = $null
                LINUX_LINK_NAME          = $null
                LINUX_SCRIPT_INTERPRETER = $null
                HASH                     = $null
                WIN_CHILD_PROCESS        = $null
                LIN_CHILD_PROCESS        = $null
                LIN_SUDO_NO_PASSWORD     = $null
            }
        }

        if ($null -ne $Policy.Applications) {
            foreach ($application in $Policy.Applications) {
                $row    = & $newRowTemplate
                $result = Measure-EpmApplication -Application $application

                $row['ApplicationName'] = $result.ApplicationName
                $row['ApplicationType'] = $result.ApplicationType
                $row['TotalWeight']     = $result.TotalWeight

                foreach ($definition in $result.ApplicationDefinition) {
                    if ($row.Contains($definition.PatternName)) {
                        $row[$definition.PatternName] = $definition.Value
                    }
                }

                $applicationsRows.Add([pscustomobject]$row)
            }
        }

        # Emit a baseline row when a policy or group has zero application definitions
        if ($applicationsRows.Count -eq 0) {
            $applicationsRows.Add([pscustomobject](& $newRowTemplate))
        }

        return $applicationsRows
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-EpmPolicyTarget {
    <#
    .SYNOPSIS
        Extracts target endpoints, executors, and accounts from an EPM policy into CSV-ready rows.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy
    )

    try {
        $targetsRows = [System.Collections.Generic.List[object]]::new()

        $policyName   = $Policy.Name
        $policyType   = $script:policyTypeMap[$Policy.PolicyType]
        $appliedToAll = $Policy.IsAppliedToAllComputers
        $policyAction = $script:actionMap[$Policy.Action]

        $newTargetRow = {
            [ordered]@{
                PolicyName                    = $policyName
                PolicyType                    = $policyType
                PolicyAction                  = $policyAction
                AppliedToAll                  = $appliedToAll
                IncludeExecutor               = $null
                ExcludeExecutor               = $null
                ExecutorType                  = $null
                IncludeUsersGroupsSid         = $null
                IncludeUsersGroupsAccountType = $null
                IncludeUsersGroupsDisplayName = $null
                IncludeUsersGroupsSamName     = $null
            }
        }

        # Process Executors if present
        $executorsProp = $Policy.PSObject.Properties['Executors']
        if ($null -ne $executorsProp -and $null -ne $executorsProp.Value -and $executorsProp.Value.Count -gt 0) {
            foreach ($executor in $executorsProp.Value) {
                $row = & $newTargetRow
                $row['ExecutorType'] = $script:executorTypeMap[$executor.ExecutorType]

                if ($executor.IsIncluded) {
                    $row['IncludeExecutor'] = $executor.Name
                } else {
                    $row['ExcludeExecutor'] = $executor.Name
                }

                $targetsRows.Add([pscustomobject]$row)
            }
        }

        # Process Accounts if present
        $accountsProp = $Policy.PSObject.Properties['Accounts']
        if ($null -ne $accountsProp -and $null -ne $accountsProp.Value -and $accountsProp.Value.Count -gt 0) {
            foreach ($account in $accountsProp.Value) {
                $row = & $newTargetRow
                $row['IncludeUsersGroupsSid']         = $account.Sid
                $row['IncludeUsersGroupsAccountType'] = $script:accountTypeMap[$account.AccountType]
                $row['IncludeUsersGroupsDisplayName'] = $account.DisplayName
                $row['IncludeUsersGroupsSamName']     = $account.SamName

                $targetsRows.Add([pscustomobject]$row)
            }
        }

        # Emit a single baseline row if neither Executors nor Accounts are defined
        if ($targetsRows.Count -eq 0) {
            $targetsRows.Add([pscustomobject](& $newTargetRow))
        }

        return $targetsRows
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-EpmPolicyProperty {
    <#
    .SYNOPSIS
        Extracts principal policy properties from an EPM policy into CSV-ready row.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [object]$Policy
    )

    try {
        $properties = [PSCustomObject]@{
            name                            = $policy.Name
            Description                     = $policy.Description
            Type                            = $script:policyTypeMap[$policy.PolicyType]
            Action                          = $script:actionMap[$policy.Action]
            Audit                           = $policy.Audit
            IsActive                        = $policy.IsActive
            Priority                        = $policy.Priority
        }

        return $properties
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Export-EpmCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ICollection]$Data,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Label
    )

    if ($Data.Count -eq 0) {
        Write-Log "No $Label found to export to CSV." WARN
        return
    }

    try {
        Write-Log "Storing $Label in $LiteralPath..." INFO
        $Data | Export-Csv -LiteralPath $LiteralPath -NoTypeInformation -Force -Encoding UTF8
    }
    catch {
        Write-Log "Failed to export $Label to $LiteralPath : $_" ERROR
        throw
    }
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

try {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    Write-Box "$scriptName"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $epmPolicies = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($EpmPoliciesExport))

    # Policies Analisys

    $policiesTarget      = [System.Collections.Generic.List[object]]::new()
    $policiesApplication = [System.Collections.Generic.List[object]]::new()
    $policiesProperties  = [System.Collections.Generic.List[object]]::new()
    $appGroupApplication = [System.Collections.Generic.List[object]]::new()

    $policyList  = @($epmPolicies.Policies)
    $totalPolicy = $policyList.Count
    $countPolicy = 0

    foreach ($policy in $policyList) {
        $countPolicy++

        Write-Log "Processing Policy [$countPolicy/$totalPolicy] - $($policy.Name)" INFO

        [object[]]$targets = Get-EpmPolicyTarget -Policy $policy
        if ($targets.Count -gt 0) { $policiesTarget.AddRange($targets) }

        [object[]]$apps = Get-EpmApplicationData -Policy $policy
        if ($apps.Count -gt 0) { $policiesApplication.AddRange($apps) }

        $prop = Get-EpmPolicyProperty -Policy $policy
        if ($null -ne $prop) { $policiesProperties.Add($prop) }
    }

    # Application Groups Analysis
    $appGroupList   = @($epmPolicies.AppGroups)
    $totalAppGroups = $appGroupList.Count
    $countAppGroup  = 0

    foreach ($appGroup in $appGroupList) {
        $countAppGroup++
        
        Write-Log "Processing Application Group [$countAppGroup/$totalAppGroups] - $($appGroup.Name)" INFO

        [object[]]$groupApps = Get-EpmApplicationData -Policy $appGroup
        if ($groupApps.Count -gt 0) { $appGroupApplication.AddRange($groupApps) }
    }
}
catch {
    Write-Log -Message "EPM analysis failed: $_" -Level ERROR
    throw
}

# Export Data to CSV

$fileNameHead = '{0}_{1}' -f $timestamp, [System.IO.Path]::GetFileNameWithoutExtension($EpmPoliciesExport)

$exports = @(
    @{ Data = $policiesTarget;      Suffix = 'PolicyTarget';          Label = 'Policies Target' }
    @{ Data = $policiesApplication; Suffix = 'PolicyApplications';    Label = 'Policies Applications' }
    @{ Data = $policiesProperties;  Suffix = 'PolicyProperties';      Label = 'Policies Properties' }
    @{ Data = $appGroupApplication; Suffix = 'AppGroupsApplications'; Label = 'Application Group Definitions' }
)

foreach ($item in $exports) {
    $outPath = Join-Path -Path $exportCsvPath -ChildPath ('{0}_{1}.csv' -f $fileNameHead, $item.Suffix)
    Export-EpmCsv -Data $item.Data -LiteralPath $outPath -Label $item.Label
}


#appCounter $EPMPolicies