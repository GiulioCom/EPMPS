<#
.SYNOPSIS
    Automates the bulk import of Application Definitions into CyberArk EPM Application Groups.

.DESCRIPTION
    This script reads application data (Publishers and Group Names) from a CSV file and 
    add them to existing or newly created Application Groups in CyberArk EPM. 
    
.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant region/instance to connect to. Used to construct the correct API URL.
    Input is validated against a known set of regions to prevent injection attacks.
    (Accepted values: login, eu, uk, au, ca, in, jp, sg, it, ch)

.PARAMETER AppDefCSV
    The Application Definition csv file having the following header:
    Publisher,AppGroupName

.PARAMETER log
    Enable logging to file and console

.PARAMETER logFolder
    Specify the log file path

.EXAMPLE
    .\Add-ApplicationDefinition.ps1' -username user@upn -tenant eu -AppDefCSV "c:\app_def_pub.csv"    

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.2
    Created: 06/2025
    Update: 04/2026
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(Mandatory = $true, HelpMessage = "Application Definition Source File")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$AppDefCSV,

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

## Invoke-RestMethod Wrapper
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
        [string]$URI,
        [string]$Method,
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 120 # Default value, in case of the returned message doesn't contain the limit info
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            $ErrorDetailsMessage = $null

            # Extract API error details if available
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try {
                    $ErrorDetailsMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Log "Failed to parse error message as JSON. Raw message: $($_.ErrorDetails.Message)" WARN
                }
            }

            # Handle rate limit error (EPM00000AE)
            if ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                # Regex pattern to find numbers followed by "minute(s)"
                $pattern = "\d+\s+minute"
                $match = [regex]::Match($ErrorDetailsMessage.ErrorMessage, $pattern)
                if ($match.Success) {
                    $minutes = [int]($match.Value -replace '\s+minute', '')
                    [int]$RetryDelay = $minutes * 60
                    Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds..." WARN
                } else {
                    Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds (default)..." WARN
                }
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } else {
                
                if ($ErrorDetailsMessage.ErrorCode -eq "EPM000002E" -and $null -ne $Body) {
                # Handle Body possible filter error 
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    Write-Log "Please verify the filter body if present, as it could be the cause of this error code." ERROR
                    throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                } elseif ($ErrorDetailsMessage.ErrorCode -eq "EPM000012E") {
                # Handle Error EPM000012E - "ErrorMessage: EPM cannot identify the following target computers that were previously selected."
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    return
                }
                else {
                # Log any other error
                    Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                    throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
                }
            }
        }
    }

    # If all retries fail, log and throw an error
    Write-Log "API call failed after $MaxRetries retries. URI: $URI" ERROR
    throw "API call failed after $MaxRetries retries."
}

## EPM RestAPI Wrappers
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
    } | ConvertTo-Json -Depth 3

    $authHeaders = @{
        "Content-Type" = "application/json"
    }

    try {
        # Write-Log "Attempting to connect to EPM tenant: $epmTenant" INFO
        $response = Invoke-EPMRestMethod -URI "https://$epmTenant.epm.cyberark.com/EPM/API/Auth/EPM/Logon" -Method 'POST' -Headers $authHeaders -Body $authBody

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

function Get-EPMSetID {
<#
.SYNOPSIS
Retrieves the ID and name of an EPM set based on the provided parameters.

.DESCRIPTION
This function interacts with the EPM API to retrieve information about sets based on the specified parameters.

.PARAMETER managerURL
The URL of the EPM manager.

.PARAMETER Headers
The authorization headers.

.PARAMETER setName
The name of the EPM set to retrieve.

.OUTPUTS
A custom object with the properties "setId" and "setName" representing the EPM set information.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$managerURL,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$setName
    )

    # Retrieve list of sets
    try {
        #Write-Log "Retrieving EPM Sets from: $managerURL" INFO
        $sets = Invoke-EPMRestMethod -URI "$managerURL/EPM/API/Sets" -Method 'GET' -Headers $Headers

        if (-not $sets -or -not $sets.Sets) {
            throw "No sets retrieved from EPM."
        }
    }
    catch {
        Write-Log "Failed to retrieve EPM Sets. Error: $_" ERROR
        throw "Could not retrieve EPM sets."
    }

    # If setName is provided, search for it directly
    if (-not [string]::IsNullOrEmpty($setName)) {
        $selectedSet = $sets.Sets | Where-Object { $_.Name -eq $setName } | Select-Object -First 1

        if ($selectedSet) {
            return [PSCustomObject]@{
                setId   = $selectedSet.Id
                setName = $selectedSet.Name
            }
        } else {
            Write-Log "Error: Set '$setName' not found in EPM." ERROR
            throw "Invalid Set Name: $setName"
        }
    }

    if ($sets.Sets.Count -eq 0) {
        Write-Log "No sets available in EPM." ERROR
        throw "No sets found. Cannot proceed."
    }

    Write-Box "Available Sets:"

    for ($i = 0; $i -lt $sets.Sets.Count; $i++) {
        Write-Log "$($i + 1). $($sets.Sets[$i].Name)" INFO DarkCyan
    }

    # Prompt user for input with max retries
    $maxRetries = 3
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"

        try {
            $chosenSetNumber = [int]$chosenSetNumber

            if ($chosenSetNumber -ge 1 -and $chosenSetNumber -le $sets.Sets.Count) {
                $chosenSet = $sets.Sets[$chosenSetNumber - 1]
                return [PSCustomObject]@{
                    setId   = $chosenSet.Id
                    setName = $chosenSet.Name
                }
            } else {
                Write-Log "Invalid selection. Please enter a number between 1 and $($sets.Sets.Count)." ERROR
            }
        }
        catch {
            Write-Log "Invalid input. Please enter a valid number." ERROR
        }
    }

    throw "Maximum attempts reached. Exiting set selection."
}

### Script function
function Test-EpmGroupCapacity {
    <#
    .SYNOPSIS
        Validates if adding new applications will exceed the EPM limit.
    .PARAMETER CurrentCount
        The number of applications currently in the EPM group.
    .PARAMETER NewItemsCount
        The number of applications being added.
    .PARAMETER GroupName
        The name of the group for logging purposes.
    .EXAMPLE
        if (Test-EpmGroupCapacity -CurrentCount 500 -NewItemsCount 10 -GroupName "MyGroup") { ... }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$CurrentCount,

        [Parameter(Mandatory = $true)]
        [int]$NewItemsCount,

        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    $EpmLimit = 1000
    $TotalPotentialCount = $CurrentCount + $NewItemsCount

    if ($TotalPotentialCount -gt $EpmLimit) {
        $RemainingSpace = [Math]::Max(0, ($EpmLimit - $CurrentCount))
        
        Write-Log "CRITICAL: Group '$GroupName' limit exceeded! Current: $CurrentCount, New: $NewItemsCount. Limit is $EpmLimit." ERROR
        Write-Log "Action: You can only add $RemainingSpace more items to this group." WARN
        
        return $false
    }

    Write-Log "Capacity Check Passed for '$GroupName': $TotalPotentialCount/$EpmLimit slots used." INFO
    return $true
}

### Begin Script ###

$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

## Prepare log folder and file
# Set default log folder if not provided
if ($log) {
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
    $logFileName = "$timestamp`_$scriptName.log"
    $logFilePath = Join-Path $logFolder $logFileName

    Write-Log "Logging enabled. Log file: $logFilePath" INFO
}
##

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

# Define common URI
$URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"

# Get the list of AppGroups and build a map for fast search
Write-Log "Retrieving the Applicaiton Groups Data..." INFO

$AppGroups = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/Search?limit=1000" -Method 'POST' -Headers $sessionHeader
$AppGroupsMap = @{}
foreach ($AppGroup in $AppGroups.Policies) {
    $AppGroupsMap[$AppGroup.PolicyName.Trim()] = $AppGroup.PolicyId
}

Write-Log "Importing data from $AppDefCSV..." INFO

# Validate CSV
$FirstRow = Import-Csv -Path $AppDefCSV | Select-Object -First 1
if (-not $FirstRow) {
    $ErrorMessage = "Schema Error: $AppDefCSV is empty or missing valid headers."
    Write-Log $ErrorMessage ERROR
    throw $ErrorMessage
}

$RawHeader = $FirstRow.psobject.properties.name
$RequiredHeaders = @('Publisher', 'AppGroupName')

foreach ($Header in $RequiredHeaders) {
    if ($Header -notin $RawHeader) {
        $ErrorMessage = "Schema Error: Missing required column '$Header' in $AppDefCSV"
        Write-Log $ErrorMessage ERROR
        throw $ErrorMessage
    }
}

# Initialize a Hashtable to store AppGroupName as the Key
# and an ArrayList of Publishers as the Value.
$AppLookup = @{}

Import-Csv -Path $AppDefCSV | ForEach-Object {
    $AppGroupName = $_.AppGroupName
    $Publisher = $_.Publisher

    if (-not $AppLookup.ContainsKey($AppGroupName)) {
        $AppLookup[$AppGroupName] = [System.Collections.Generic.List[string]]::new()
    }
    $AppLookup[$AppGroupName].Add($Publisher)
}

foreach ($Entry in $AppLookup.GetEnumerator()) {
    
    $TargetAppGroupName = $Entry.Key
    $Publishers = $Entry.Value

    $AppDefinitions = @(foreach ($PublisherName in $Publishers) {
        if ([string]::IsNullOrWhiteSpace($PublisherName)) { continue }

        [PSCustomObject]@{
            "internalId"= 0
            "applicationType"= 3
            "displayName"= ""
            "description"= ""
            "patterns"= @{
                "PUBLISHER"= @{
                "@type"= "Publisher"
                "signatureLevel"= 2
                "separator"= ";"
                "caseSensitive"= $false
                "compareAs"= 2 # Contains
                "isEmpty"= $false
                "content"= $PublisherName.Trim()
                }
            }
            "childProcess"= $true
            "restrictOpenSaveFileDialog"= $true
        }
    })    
    
    # Search the App Group in the Map
    if ($AppGroupsMap.ContainsKey($TargetAppGroupName)) {
        $targetAppGroupId = $AppGroupsMap[$TargetAppGroupName]
        Write-Log "Match Found: App Group '$TargetAppGroupName' has ID: $targetAppGroupId" -severity INFO
        
        $appGroup = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/$targetAppGroupId" -Method 'GET' -Headers $sessionHeader

        if (-not (Test-EpmGroupCapacity -CurrentCount $appGroup.Policy.Applications.Count -NewItemsCount $AppDefinitions.Count -GroupName $TargetAppGroupName)) {
            continue # Skip this group
        }
        
        $finalAppList = [System.Collections.Generic.List[object]]::new($appGroup.Policy.Applications)
    
        foreach ($Def in $AppDefinitions) { $finalAppList.Add($Def) }

        # Update the object reference
        $appGroup.Policy.Applications = $finalAppList
        $AppGroupJSON = $AppGroup.Policy | ConvertTo-Json -Depth 10 -Compress
    
        # Update the AppGroup
        $UpdateResponse = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups/$targetAppGroupId" -Method 'PUT' -Headers $sessionHeader -Body $AppGroupJSON
        if ($null -ne $UpdateResponse -and $null -ne $UpdateResponse.Id) {
            Write-Log "SUCCESS: Group '$($UpdateAppGroup.Name)' updated. Now contains $($UpdateResponse.Applications.Count) application(s)." INFO
        }
    } else {
        Write-Log "Group '$TargetAppGroupName' not found in EPM. Creating the Application Group..." -severity WARN

        if (-not (Test-EpmGroupCapacity -CurrentCount 0 -NewItemsCount $AppDefinitions.Count -GroupName $TargetAppGroupName)) {
            continue # Skip this group
        }

        $NewAppGroup = @{
            "Name" = $TargetAppGroupName
            "PolicyType" = 14
            "Applications" = $AppDefinitions
        } | ConvertTo-Json -Depth 10 -Compress

        # Create the AppGroup
        $AddResponse = Invoke-EPMRestMethod -Uri "$URI/Policies/ApplicationGroups" -Method 'POST' -Headers $sessionHeader -Body $NewAppGroup
        if ($null -ne $AddResponse -and $null -ne $AddResponse.Id) {
            Write-Log "SUCCESS: New Application Group '$($AddResponse.Name)' created with ID: $($AddResponse.Id)." -severity INFO
        }
    }
}
