<#
.SYNOPSIS
    Find duplicated Publisher entries in Application Groups

.DESCRIPTION
    Index for definition having publisher only, and search whetever another definition is with the same publisher and other data

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER EPMPoliciesFile
    Export of EPM policies.

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1 - POC
    Date: 04/2026

.RELEASE NOTES
    04/2026 - Initial Version

.EXAMPLE
    1. .\New-FindEPMDuplicatePublisher.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -EPMPoliciesFile ""
#>

param (
#    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
#    [string]$username,

#    [Parameter(HelpMessage="Please enter valid EPM set name")]
#    [string]$setName = "",

#    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
#    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
#    [string]$tenant,

    [Parameter(HelpMessage = "Specify the EPM policy file")]
    [ValidateScript({
        $extension = [System.IO.Path]::GetExtension($_)
        if ($extension -notmatch '^\.(json|epmp)$') {
            throw "Security Exception: Invalid file type. Only .json or .epmp permitted."
        }
        if (Test-Path -LiteralPath $_ -PathType Leaf) {
            $true
        } else {
            throw "File not found or is a directory: $_"
        }
    })]
    [string]$EPMPoliciesFile = ".\Policies\data\Volvo_Policies-29-Apr-26_08-10-38.epmp.json",

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
        Add-Content -Path $logFilePath -Value $logMessage
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
        "Severity" = "INFO"
        "ForegroundColor" = "Cyan"
    }

    Write-Log $horizontalLine @textProp
    Write-Log $centeredText   @textProp
    Write-Log $horizontalLine @textProp
}
##

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

            if ($null -eq $ErrorDetailsMessage) {
                $GenericError = "$URI - HTTP Error: $($_.Exception.Message)"
                Write-Log $GenericError ERROR
                throw $GenericError
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
        $message = "Failed to retrieve EPM Sets. Error: $_" 
        Write-Log $message ERROR
        throw $message
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

####

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

$jsonContent = Get-Content -LiteralPath $EPMPoliciesFile -Raw
$epmData = ConvertFrom-Json -InputObject $jsonContent

$PublisherOnlyMap = @{}
$ComplexRulesList = [System.Collections.Generic.List[psobject]]::new()

$AppGroupPolicyMap = @{}

# Loop through the structured data
foreach ($appGroup in $epmData.AppGroups) {
    
    Write-Log "Processing Application Group '$($appGroup.Name)'" INFO

    # Searching in which policy
    foreach ($policy in $epmData.Policies) {
        foreach ($app in $policy.Applications) {
            
            if ($app.displayName -eq $appGroup.Name) {

                # Create the object we want to store
                $policyData = [pscustomobject]@{
                    PolicyId     = $policy.Id
                    PolicyName   = $policy.Name
                    PolicyType   = $policy.PolicyType
                    PolicyAction = $policy.Action
                }

                if ($AppGroupPolicyMap.ContainsKey($appGroup.Name)) {
                #   Write-Log "Duplicate Publisher-Only rule found for '$pubName' in AppGroup: $($PublisherOnlyMap[$pubName].AppGroupName)" WARN
                    $AppGroupPolicyMap[$appGroup.Name].Add($policyData)
                } else {
                    $newPolicyList = [System.Collections.Generic.List[psobject]]::new()
                    $newPolicyList.Add($policyData)
                    $AppGroupPolicyMap[$appGroup.Name] = $newPolicyList
                }
            }
        }    
    }
    
    foreach ($app in $appGroup.Applications) {

        $hasPublisher = $null -ne $app.patterns.PUBLISHER
        $patternCount = [int]@($app.patterns.psobject.properties).Count
        
        if ($hasPublisher -and $patternCount -eq 1) {
            $pubName = $app.patterns.PUBLISHER.content
            
            # Security Mitigation: Ensure we don't attempt to use a null/empty key
            if ([string]::IsNullOrWhiteSpace($pubName)) {
                Write-Log "Encountered an empty Publisher name in AppGroup: $($appGroup.Name). Skipping." WARN
                continue 
            }

            # Create the object we want to store
            $groupData = [pscustomobject]@{
                AppGroupId   = $appGroup.Id
                AppGroupName = $appGroup.Name
            }

            # Check if this Publisher is already in our Hash Table
            if ($PublisherOnlyMap.ContainsKey($pubName)) {
                Write-Log "Duplicate Publisher-Only rule found for '$pubName' in AppGroup: $($PublisherOnlyMap[$pubName].AppGroupName)" WARN
                $PublisherOnlyMap[$pubName].Add($groupData)
            } else {
                $newList = [System.Collections.Generic.List[psobject]]::new()
                $newList.Add($groupData)
                $PublisherOnlyMap[$pubName] = $newList
            }
        } elseif ($hasPublisher -and $patternCount -gt 1) {
            # MATCH 2: Publisher PLUS other criteria
            $ComplexRulesList.Add([pscustomobject]@{
                AppGroupId   = $appGroup.Id
                AppGroupName = $appGroup.Name
                Publisher    = $app.patterns.PUBLISHER.content
                AppId        = $app.id
                AppDescr     = $app.description
                # You might also want to store $app.Id or $app.Name here to identify the specific complex rule
            })
        }
    }
}

#Write-Log "Found $($PublisherOnlyMap.Count) Publisher-Only rules." INFO
#Write-Log "Found $($ComplexRulesList.Count) Complex rules." INFO

$RedundantCandidates = [System.Collections.Generic.List[psobject]]::new()

foreach ($complexRule in $ComplexRulesList) {
    
    $pubToFind = $complexRule.Publisher

    if ([string]::IsNullOrWhiteSpace($pubToFind)) { 
        continue 
    }

    if ($PublisherOnlyMap.ContainsKey($pubToFind)) {
        
        $srcAppGroups = $PublisherOnlyMap[$pubToFind].AppGroupName -join ' - '
        foreach ($AppGroup in $PublisherOnlyMap[$pubToFind].AppGroupName){
            $srcPoliciesName = $AppGroupPolicyMap[$AppGroup].PolicyName -join ' - '
            $srcPoliciesActions = $AppGroupPolicyMap[$AppGroup].PolicyAction -join ' - '
        }
        

        # Store the finding as a custom object for easy reporting
        $RedundantCandidates.Add([pscustomobject]@{
            PublisherName  = $pubToFind
            AppGroup       = $complexRule.AppGroupName
            Policy         = $AppGroupPolicyMap[$complexRule.AppGroupName].PolicyName
            Action         = $AppGroupPolicyMap[$complexRule.AppGroupName].PolicyAction
          #  AppId         = $complexRule.AppId
            AppDescr       = $complexRule.AppDescr
            SourceAppGroup = $srcAppGroups
            SourcePolicies = $srcPoliciesName
            SourceAction   = $srcPoliciesActions

        })
    }
}

# Output the total count of findings
Write-Log "Correlation complete. Found $($RedundantCandidates.Count) potentially redundant rules." INFO
#$RedundantCandidates | Format-Table -AutoSize
$RedundantCandidates | ConvertTo-Csv -NoTypeInformation


<#
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

# Define common URI
$URI = "$($login.managerURL)/EPM/API/Sets/$($set.setId)"

Write-Log "Entering SET: $($set.setName)..." INFO -ForegroundColor Blue
#>