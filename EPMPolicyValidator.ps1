<#
.SYNOPSIS
    This script validates EPM applications definition.

.DESCRIPTION
    The EPMPolicyValidator script aims to scan policies or application groups, collect information about
    the application definitions, and validate them. It operates in two modes:

    1. **Audit Mode**: Analyzes the Audit SET Admins events for policy changes and processes only the modified
       policies. This mode is useful for continuous analysis of policies upon administrator modifications and is
       suggested to be used as a scheduled task running every 5 minutes.
    
    2. **Manual Scan Mode**: Performs a one-time scan of policies for testing or health checks. The script can
       manually scan all application groups and policies, only application groups, only policies, or specific
       policies or application groups.

.PARAMETER username
    Mandatory: Yes
    The EPM username (e.g., user@domain).

.PARAMETER setName
     Mandatory: No
    The name of the EPM set.

.PARAMETER tenant
    Mandatory: Yes
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder
    Mandatory: Conditional
    Specifies the folder where data will be stored. This parameter is mandatory in Audit Mode.

.PARAMETER ScanPolicies
    Mandatory: No
    Specifies the type of policy scanning to perform. Valid values are 'all', 'appgroups', or 'policies'.

.PARAMETER name
    Mandatory: No
    Specifies the name of the policy or application group when using the -ScanPolicies parameter.

.EXAMPLE
    1. Audit Mode:
        .\EPMPolicyValidator.ps1 -username "user@domain" -tenant "eu" -destinationFolder "C:\Data"
    2. Manual Mode:
        .\EPMPolicyValidator.ps1 -username "user@domain" -tenant "eu" -ScanPolicies "all"

.NOTES
    File: EPMPolicyValidator.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.6
    Created: 02/2024
    Last Modified: 05/2024
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName = "",

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [string]$tenant,

    [Parameter(HelpMessage = "Please provide the destination folder to store data")]
    [string]$destinationFolder,

    [Parameter(HelpMessage = "Scan policies option: 'all', 'appgroups', or 'policies'")]
    [ValidateSet("all", "appgroups", "policies")]
    [string]$ScanPolicies,

    [Parameter(HelpMessage = "Policy \ App Group name, to be used with -ScanPolicies if needed")]
    [string]$name
)
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
                Write-Host $ErrorDetailsMessage.ErrorMessage
                Write-Host "Retrying in $apiDelaySeconds seconds..."
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
            Write-Host "Available Sets:"
            $numberSets = 0
            foreach ($set in $sets.Sets) {
                Write-Host "$($numberSets + 1). $($set.Name)"
                $numberSets++
            }
        
            # Ask the user to choose a set by number
            $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"
        
            # Validate the chosen set number
            try {
                $chosenSetNumber = [int]$chosenSetNumber
        
                if ($chosenSetNumber -lt 1 -or $chosenSetNumber -gt $numberSets) {
                    Write-Error "Invalid set number. Please enter a number between 1 and $numberSets."
                } else {
                    # Set chosenSet based on the user's selection
                    $chosenSet = $sets.Sets[$chosenSetNumber - 1]
                    $setId = $chosenSet.Id
                    $setName = $chosenSet.Name
                }
            } catch {
                Write-Error "Invalid input. Please enter a valid number."
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
            Write-Error "$SetName : Invalid Set"
            return
        }
    }

    # Return a custom object with set information
    [PSCustomObject]@{
        setId   = $setId
        setName = $setName
    }
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
    }

    # Manage use case
    if (!$Application.patterns.$PatternName.isEmpty) {
        
        $result.Weight = $Priority

        # Manage exceptions

        # Reduce weight if the compareAs is not EXACTLY
        # But before, check compareAs is available (for example the property LOCATION doesn't have it)
        if ($null -ne $Application.patterns.$PatternName -and $null -ne $Application.patterns.$PatternName.compareAs) {
            if ($Application.patterns.$PatternName.compareAs -ne 0) {
                $result.Weight = $result.Weight / 2
            }
        }
        
        # Publisher: Reduce weight if the publicher is not SPECIFIC
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
        2 = "Group"
        3 = "EXE"
        4 = "Script"
        5 = "MSI"
        6 = "MSU"
        7 = "WebApp"
        8 = "WinAdminTask"
        9 = "ActiveX"
        13 = "FileSystemNode"
        14 = "Registry Key"
        15 = "COM"
        17 = "WinService"
        18 = "USB Device"
        19 = "Optical Disc2"
        20 = "WinApp"
        21 = "DLL"
        28 = "Linux command"
    }
   
    $compareAsMapping = @{
        0 = "exact"
        1 = "prefix"
        2 = "contains"
        3 = "wildcards"
        4 = "regExp"
    }

    $priority1 = 30
    $priority2 = 20
    $priority3 = 10

    # Set the threshold, the value can change based on policy type or policy action
    # Policy action allow or deny
    # Policy type Linux
    $threshold = 0
    
    if ($action -eq 2 -or $action -eq 1) {
        $threshold = 30
    } elseif ($PolicyType -eq 12) {
        $threshold = 60
    } else {
        $threshold = 90
    }
    
    $unspportedAppType = $false    

    $matchedConditions = @()
    $totalWeight = 0

    $appTypeName = $AppTypeMapping[$Application.applicationType]

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
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
            # If child process is enabled divide the total            
            if ($Application.childProcess -eq $true) {
                $totalWeight = $totalWeight / 2
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Enabled"
                } 
            } else {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Disabled"
                }
            }
        }
        'Script' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
            # If child process is enabled divide the total            
            if ($Application.childProcess -eq $true) {
                $totalWeight = $totalWeight / 2
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Enabled"
                } 
            } else {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Disabled"
                }
            }
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
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
        }
        'MSU' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            $matchedConditions += Evaluate-Patterns $Application "PARENT_PROCESS" $priority3
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
        }
        'ActiveX' {
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
        }
        'COM' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION_TYPE" $priority2
            $matchedConditions += Evaluate-Patterns $Application "OWNER" $priority3
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
        }
        'WinApp' {
            $matchedConditions += Evaluate-Patterns $Application "PUBLISHER" $priority1
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
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
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }
            # If child process is enabled divide the total            
            if ($Application.childProcess -eq $true) {
                $totalWeight = $totalWeight / 2
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Enabled"
                } 
            } else {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "WIN_CHILD_PROCESS"
                    Weight = "Disabled"
                }
            }
        }
        'Linux command' {
            $matchedConditions += Evaluate-Patterns $Application "FILE_NAME" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LOCATION" $priority1
            $matchedConditions += Evaluate-Patterns $Application "ARGUMENTS" $priority1
            $matchedConditions += Evaluate-Patterns $Application "LINUX_LINK_NAME" $priority3
            $matchedConditions += Evaluate-Patterns $Application "LINUX_SCRIPT_INTERPRETER" $priority2
            # Checksum can't be managed by external funtion
            if ($Application.patterns.FILE_NAME.hash) {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "HASH"
                    Weight = $priority2
                }
            }
            # Sum the total weight
            foreach ($condition in $matchedConditions) {
                $totalWeight += $condition.Weight
            }

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
                Weight = "$linuxChildProcessName"
            }
        
            # Linux Sudo no password
            if ($Application.linuxSudoNoPassword -eq $true) {
                $totalWeight = $totalWeight / 2
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "LIN_SUDO_NO_PASSWORD"
                    Weight = "Enabled"
                }
            } else {
                $matchedConditions += [PSCustomObject]@{
                    PatternName = "LIN_SUDO_NO_PASSWORD"
                    Weight = "Disabled"
                }
            }
            
        }
        default {
            # Default action if none of the conditions match
            Write-Host "Application Type $appTypeName not supported"
            $unspportedAppType = $true
        }
    }

    if (!$unspportedAppType) {

        # Define the application name for a better output
        $applicationName = $null
        #Write-Host $matchedConditions
        foreach ($condition in $matchedConditions) {
            if ($condition.Weight -ge 15) {
                switch ($condition.PatternName) {
                    "FILE_NAME" {
                        $applicationName = $Application.patterns.FILE_NAME.content
                        break
                    }
                    "ORIGINAL_FILE_NAME" {
                        $applicationName = $Application.patterns.ORIGINAL_FILE_NAME.content
                        break
                    }
                    "PUBLISHER" {
                        $applicationName = $Application.patterns.PUBLISHER.content
                        break
                    }
                }
                if ($applicationName) {
                    break  # Stop the loop if $applicationName is assigned
                }
            }
        }
        
        if (-not $applicationName) {
            # If none of the conditions matched, assign $Application.id
            $applicationName = $Application.id
        }          
        
        If ($totalWeight -ge $threshold){
            Write-Host "$applicationName - $totalWeight - Compliant to Policy Standards" -ForegroundColor Green
        } else {
            Write-Host "$applicationName - $totalWeight - Not Compliant to Policy Standards" -ForegroundColor Red
        }
        Write-Host "Application Type: $appTypeName" -ForegroundColor DarkMagenta
        Write-Host "Application Description: $($Application.description)"  -ForegroundColor DarkMagenta
        # Iterate through $matchedConditions
        foreach ($condition in $matchedConditions) {
            # Print PatternName if Weight is greater than 0
            if ($condition.Weight -ne 0) {
                Write-Host "PatternName: $($condition.PatternName) = $($condition.Weight)"
            }
        }
    }
    
    Write-Host "Press Enter to continue..."
    $null = Read-Host
}

function Get-PolicyInfo {
<#
.SYNOPSIS
Retrieves information about policies from a management system using REST API calls.

.DESCRIPTION
The Get-PolicyInfo function retrieves information about policies from a management system using REST API calls. It allows querying policies based on specified criteria such as policy name, set ID, and feature type. Depending on the feature type, it searches for policies either within application groups or directly within the policies.

.PARAMETER managerURL
The URL of the management system.

.PARAMETER Headers
Headers to be included in the HTTP request.

.PARAMETER setID
The ID of the policy set.

.PARAMETER policyName
The name of the policy to retrieve.

.PARAMETER feature
The type of feature to search for. Accepted values: "Application Groups", "Policy".

.OUTPUTS
Information about policies and their associations.

.NOTES
- The function uses REST API calls to interact with the management system.
- It relies on helper functions Invoke-EPMRestMethod and Process-Application for certain operations.

.EXAMPLE
Get-PolicyInfo -managerURL "https://example.com" -Headers @{ "Authorization" = "Bearer token" } -setID "123456" -policyName "PolicyName" -feature "Application Groups"
This command retrieves information about policies associated with the specified policy name within application groups.
#>
    param (
        [string]$managerURL,
        [hashtable]$Headers,
        [string]$setID,
        [string]$policyName,
        [string]$feature,
        [object]$appGroupList,
        [object]$policesList
    )

    $actionMapping = @{
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

    $policyType = @{
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

    $applicationGroupType = @{
        14 = "Application Group Win"
        15 = "Application Group Linux"
        43 = "Predefined App Groups Win"
    }

    # Filter by Application Group Win, Predefined App Groups Win, Application Group Linux
    $allowedApplicationGroupType = @(14, 43, 15)
    $supportedApplicationGroupTypes = $allowedApplicationGroupType | Where-Object { $applicationGroupType.ContainsKey($_) } | ForEach-Object { $applicationGroupType[$_] }

    $allowedPolicyType = @(11, 18, 12)
    $supportedPolicyTypes = $allowedPolicyType | Where-Object { $policyType.ContainsKey($_) } | ForEach-Object { $policyType[$_] }
    
    
    # Construct the base URI for API calls
    $policiesURI = "$managerURL/EPM/API/Sets/$setID/Policies"

    # Retrieve policy list based on the feature type
    if ($feature -eq "Application Groups") {
        # Retrieve application groups and filter by policy name
        # Search AppGroup
        foreach ($appGroup in $appGroupList.Policies) {
            if ($appGroup.PolicyName -eq $policyName) {
                # Filter by Allowed Application Groups
                if ($allowedApplicationGroupType -contains $appGroup.PolicyType) {
                    # Get Application Group Details
                    $appGroupDetails = Invoke-EPMRestMethod -Uri "$policiesURI/ApplicationGroups/$($appGroup.PolicyId)" -Method 'GET' -Headers $Headers    

                    # Search policy where the app ID is included
                    foreach ($policy in $policiesList.Policies) {

                        foreach ($refAppGroups in $policy.ReferencedApplicationGroups) {
                            if ($refAppGroups.Id -eq $appGroup.PolicyId) {
                                $policyTypeName = $policyType[$policy.PolicyType]
                                $policyAction = $actionMapping[$policy.Action]
                                Write-Host "The application group '$($appGroup.PolicyName)' - $($appGroup.Description)" -ForegroundColor Green
                                Write-Host "Was found in the '$($policy.PolicyName)' policy - $($policy.Description)" -ForegroundColor Green
                                Write-Host "Categorized as '$policyTypeName' with the action set to '$policyAction'" -ForegroundColor Green
                                # Filter by Allowed Policies
                                if ($allowedPolicyType -contains $policy.PolicyType) {
                                    foreach ($application in $appGroupDetails.Policy.Applications) {
                                        Process-Application -Application $application -PolicyType $($policy.PolicyType) -action $($policy.Action)
                                    }
                                } else {
                                    Write-Host "Policy '$($policy.PolicyName)' not supported. The supported policy types are: $($supportedPolicyTypes -join ', ')" -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                } else {
                    Write-Host "Application Group '$($appGroup.PolicyName)' not supported. The supported application group type are $($supportedApplicationGroupTypes -join ', ')" -ForegroundColor Yellow
                }    
            }
        }
    } else {
        #Search policy
        $policyFound = $false
        foreach ($policy in $policiesList.Policies) {
            if ($policy.PolicyName -eq $policyName) {
                $policyTypeName = $policyType[$policy.PolicyType]
                $policyAction = $actionMapping[$policy.Action]
                Write-Host "Policy '$policyName' - $($policy.Description) was found"
                Write-Host "Categorized as '$policyTypeName' with the action set to '$policyAction'" -ForegroundColor Green

                # Filter by Allowed Policies type
                if ($allowedPolicyType -contains $policy.PolicyType) {
                    $policyFound = $true
                    $policyDetails = Invoke-EPMRestMethod -Uri "$policiesURI/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
                    foreach ($application in $policyDetails.Policy.Applications) {
                        Process-Application -Application $application -PolicyType $($policy.PolicyType) -action $($policy.Action)
                    }
                }
            }
        }
        
        if ($policyFound -eq $false) {
            Write-Host "Policy '$PolicyName' not supported. The supported policy types are: $($supportedPolicyTypes -join ', ')" -ForegroundColor Yellow
        }
    }
}


### Begin Script ###

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"

# Authenticate
$login = Connect-EPM -credential $credential -epmTenant $tenant

# Create a session header with the authorization token
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

# Check if the -ScanPolicies switch is present
if ($PSBoundParameters.ContainsKey('ScanPolicies')) {
    switch ($ScanPolicies) {
        "all" {
            # Perform actions for scanning all policies
            Write-Host "Scanning Policies and Application Groups." -ForegroundColor DarkMagenta

            $appGroupsFilter = @{
                "filter" = "PolicyGroupType EQ 10" # Application Group -> Custom Application Group, Predefined App Group, Predefined Trusted Source 
            }  | ConvertTo-Json
            $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
            
            $policiesFilter = @{
                "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
            }  | ConvertTo-Json    
            $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

            # Get Application Groups
            Write-Host "Scanning App Groups..." -ForegroundColor DarkMagenta
            $appGroupsCounter = 1

            foreach ($appGroup in $appGroupList.Policies) {
                Write-Host "$appGroupsCounter\$($appGroupList.FilteredCount) Application Group - $($appGroup.PolicyName)" -ForegroundColor Green
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($appGroup.PolicyName) -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
                $appGroupsCounter++
            }

            # Get Policyes list
            Write-Host "Scanning Policies..." -ForegroundColor DarkMagenta
            $policyCounter = 1
            
            foreach ($policy in $policiesList.Policies) {
                Write-Host "$policyCounter\$($policiesList.FilteredCount) Policy - $($policy.PolicyName)" -ForegroundColor Green
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($policy.PolicyName) -feature "Server" -policiesList $policiesList
                $policyCounter++
            }
        }
        "appgroups" {
            # Perform action for scanning by application group
            if ($PSBoundParameters.ContainsKey('name')) {
                # Perform actions for scanning selected application group
                Write-Host "Scanning by application group: $name"

                # Get the Application Group
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader

                # Get the Policies
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $name -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
            } else {
                # Perform actions for scanning all application groups
                Write-Host "Scanning all Application Groups." -ForegroundColor DarkMagenta

                $appGroupsFilter = @{
                    "filter" = "PolicyGroupType EQ 10" # Application Group -> Custom Application Group, Predefined App Group, Predefined Trusted Source 
                }  | ConvertTo-Json
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
                
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json    
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

                $appGroupsCounter = 1
                # Get Application Groups
                foreach ($appGroup in $appGroupList.Policies) {
                    Write-Host "$appGroupsCounter\$($appGroupList.FilteredCount) Application Group - $($appGroup.PolicyName)" -ForegroundColor Green
                    Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($appGroup.PolicyName) -feature "Application Groups" -appGroupList $appGroupList -policiesList $policiesList
                    $appGroupsCounter++
                }
            }
        }
        "policies" {
            # Perform action for scanning by policy name
            if ($PSBoundParameters.ContainsKey('name')) {
                # Perform actions for scanning selected policy name
                Write-Host "Scanning by policy name: $name"

                # Get the Application Group
                $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader

                # Get the Policies
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $name -feature "Server" -appGroupList $appGroupList -policiesList $policiesList
            } else {
                # Perform actions for scanning all policies
                Write-Host "Scanning all Policies." -ForegroundColor DarkMagenta

                # Get Policies list
                $policiesFilter = @{
                    "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                }  | ConvertTo-Json    
                $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter

                $policyCounter = 1
                
                foreach ($policy in $policiesList.Policies) {
                    Write-Host "$policyCounter\$($policiesList.FilteredCount) Policy - $($policy.PolicyName)" -ForegroundColor Green
                    Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $($policy.PolicyName) -feature "Server" -policiesList $policiesList
                    $policyCounter++
                }
            }
        }
        default {
            Write-Host "Invalid value for -ScanPolicies. Accepted values are 'All', 'AppGroup', 'Policies'."
            exit
        }
    }
# Default mode: Perform scan from SetAdmin Audit
} else {

    $appGroupList = ""
    $policiesList = ""
    $eventsNumber = 0
    $lastEventTime
    $filename = "lastProcessedEvent.txt"

    # Check if the 'DestinationFolder' parameter is provided
    if (!$PSBoundParameters.ContainsKey('DestinationFolder')) {
        do {
            # Prompt the user to enter the destination folder
            $destinationFolder = Read-Host -Prompt "Please provide the destination folder to store data"
            
            # Check if the provided value is valid
            if ([string]::IsNullOrWhiteSpace($destinationFolder)) {
                Write-Host "Destination folder is required." -ForegroundColor Red
            }
        } while ([string]::IsNullOrWhiteSpace($destinationFolder))
    }

    # Prepare destination Folder used to store Last Events Time analyzed
    # Sanitize SET name, could contain charater not allowed
    $destSetName = $set.SetName -replace ('\[|\]|\/', '')
    $destinationFolder = "$destinationFolder\$destSetName"
    $lastProcessedEventFile = Join-Path -Path $destinationFolder -ChildPath $filename

    # Create Folder
    try {
        New-Item -ItemType Directory -Path $destinationFolder -Force -ErrorAction Stop | Out-Null
    } catch {
        # Handle errors if necessary
        Write-Host "Error creating directory: $_"
    }

    # Check the file
    try {
        # Check if the file exists
        
        if (!(Test-Path -Path $lastProcessedEventFile -PathType Leaf)) {
            # If the file does not exist, continue with the rest of the code
            Write-Host "The $filename file does not exist in the folder."
        } else {
            $lastEventTime = Get-Content -Path $lastProcessedEventFile -TotalCount 1
        }
    } catch {
        # Handle errors if necessary
        Write-Host "Error loading $filename"
    }

    if ([string]::IsNullOrWhiteSpace($lastEventTime)) {
        $URLParm = "Limit=500"
    } else {
        $URLParm = "DateFrom=$lastEventTime"
    }

    $setAdminsAudits = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/AdminAudit?$URLParm" -Method 'GET' -Headers $sessionHeader

    # Order events by EventTime
    $setAdminsAuditsSortByEventTime = $setAdminsAudits.AdminAudits | Sort-Object -Property EventTime
    
    Write-Host "Searching for Audit Events..." -ForegroundColor DarkMagenta
    foreach ($setAdminsAudit in $setAdminsAuditsSortByEventTime) {
        if ($setAdminsAudit.PermissionDescription -eq "Create Policy" -or $setAdminsAudit.PermissionDescription -eq "Change Policy") {
            $pattern = '.*\"(.*?)\".*'
            if ($setAdminsAudit.Description -match $pattern) {
                $policyName = $Matches[1]
                $eventsNumber++
                Write-Host "$eventsNumber. $($setAdminsAudit.Feature): $policyName"
                
                # Get the Application Group only the first time to reduce the EPM request
                if ($appGroupList -eq "") {
                    $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader
                }

                # Get the Policies only the first time to reduce the EPM request
                if ($policiesList -eq "") {
                    $policiesFilter = @{
                        "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
                    }  | ConvertTo-Json
                    $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
                }
                
                Get-PolicyInfo -managerURL $($login.managerURL) -Headers $sessionHeader -setId $($set.setId) -policyName $policyName -feature $($setAdminsAudit.Feature) -appGroupList $appGroupList -policiesList $policiesList
            } else {
                Write-Host "No match found for $($setAdminsAudit.Description)."
            }
        }

        # Update last event time
        $lastEventTime = $setAdminsAudit.EventTime
        #Write-Host $lastEventTime
    }

    # Provide events results
    if ($eventsNumber -eq 0) {
        Write-Host "No event processed"
    } else {
        Write-Host "Processed $eventsNumber events"
    }

    # Write the value of $lastEventTime to the lastProcessedEvent.txt file
    try {
        $lastEventTime | Set-Content -Path $lastProcessedEventFile -Encoding UTF8 -ErrorAction Stop
        Write-Host "Successfully wrote last event time to $lastProcessedEventFile"
    } catch {
        Write-Host "Error writing to $lastProcessedEventFile"
    }
}
