<#
.SYNOPSIS
    

.DESCRIPTION
Demo Script update policy propertiers massively, in this example script enabling policy audit if not enabled 

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMPolicyUpdateExample.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 1
    Created: 07/2024
    Last Modified: 07/2024
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

    [switch]$RemoveDuplicatedPolicy,
    [switch]$RemoveImportedFlag,
    [switch]$EnableAudit
)

# Function to log messages to console and file
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

##############

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


if ($EnableAudit) {
    # Retrieve Policies
    # Filter only advanced Windows Policy
    $policiesSearchFilter = @{
        "filter" = "PolicyType EQ ADV_WIN"
    } | ConvertTo-Json

    $policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter

    # Set the Counter
    $policyCounter = 1 
    
    Write-Log "Found $($policySearch.FilteredCount) policies" INFO

    # Process each policy
    foreach ($policy in $policySearch.Policies) {

        Write-Log "Processing $policyCounter of $($policySearch.FilteredCount): $($policy.PolicyName)" INFO

        # Filter only the actions: Block, Elevate, Elevate If Necessary
        if ($policy.Action -eq 1 -or $policy.Action -eq 3 -or $policy.Action -eq 4) {
        
            # Retrive the policy and save in temp file
            $getPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
                
            $Audit = $getPolicyDetails.Policy.Audit
            if ($Audit -ne $true) {
                Write-Log "$($policy.PolicyName): Audit disabled" INFO
                $getPolicyDetails.Policy.Audit = $true
                Write-Log "$($policy.PolicyName): Enabling Audit" INFO
                $updatePolicyJson = $getPolicyDetails.Policy | ConvertTo-Json -Depth 10
                $updatePolicy = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body ([System.Text.Encoding]::UTF8.GetBytes($updatePolicyJson)) # to handle special char
                Write-Log "$($policy.PolicyName): updated correctly - audit enabled" INFO
            } else {
                Write-Log "$($policy.PolicyName): Nothing to do, Policy Audit enabled" INFO
            }
        } else {
            Write-Log "$($policy.PolicyName): Policy Action Allow not in scope" WARN
        }

        $policyCounter++
    }
}

if ($RemoveDuplicatedPolicy) {

    $policiesSearchFilter = @{
        "filter" = "PolicyType EQ ADV_WIN"
    } | ConvertTo-Json

    $policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter
    
    Write-Log "Found $($policySearch.FilteredCount) of a total $($policySearch.TotalCount) policies" INFO

    # Initialize hashtables
    $policiesWithoutSuffix = @{}
    $policiesWithSuffix = @{}

    # Iterate through the policies
    foreach ($policy in $policySearch.Policies) {
        $policyName = $policy.PolicyName
        $policyID = $policy.PolicyID

        # Check if the policy name ends with " (\d+)"
        if ($policyName -match " \(\d+\)$") {
            # Add to the hashtable for policies with suffix
            if (-not $policiesWithSuffix.ContainsKey($policyName)) {
                $policiesWithSuffix[$policyName] = @()
            }
            $policiesWithSuffix[$policyName] += $policyID
        } else {
            # Add to the hashtable for policies without suffix
            if (-not $policiesWithoutSuffix.ContainsKey($policyName)) {
                $policiesWithoutSuffix[$policyName] = @()
            }
            $policiesWithoutSuffix[$policyName] += $policyID
        }
    }

    $counter

    # Process policies in PoliciesWithSuffix and search in PoliciesWithoutSuffix
    foreach ($policyNameWithSuffix in $policiesWithSuffix.Keys) {
        # Remove the suffix " (number)" to get the base policy name
        $basePolicyName = $policyNameWithSuffix -replace " \(\d+\)$", ""

        # Check if the base policy name exists in PoliciesWithoutSuffix
        if ($policiesWithoutSuffix.ContainsKey($basePolicyName)) {
            $policyIdsWithSuffix = $policiesWithSuffix[$policyNameWithSuffix]
            $policyIdsWithoutSuffix = $policiesWithoutSuffix[$basePolicyName]

            # Process the matching policies (example: just output the details)
            Write-Log "$counter/$($policiesWithSuffix.Count) Found matching policy: $basePolicyName -> ID: $($policyIdsWithoutSuffix))" INFO
            Write-Log "  Duplicated Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            Write-Log "  Removing Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policyIdsWithSuffix)" -Method 'DELETE' -Headers $sessionHeader
            Write-Log "  Removed Policy: $policyNameWithSuffix -> ID: $($policyIdsWithSuffix)" WARN
            
            # Additional processing can be done here if needed
        } else {
            Write-Log "$policyNameWithSuffix not duplicated" INFO
        }

        $counter++
        
    }
}

if ($RemoveImportedFlag) {

    # Request Policies name contains [IMPORTED] keyword
    $policiesSearchFilter = @{
        "filter" = "PolicyName CONTAINS [IMPORTED]"
    } | ConvertTo-Json

    $policySearch = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $policiesSearchFilter
    
    Write-Log "Found $($policySearch.FilteredCount) of a total $($policySearch.TotalCount) policies" INFO

    $counter = 1
    
    foreach ($policy in $policySearch.Policies) {
               
        if ($policy.PolicyName -match "^\[IMPORTED\] .*$") {
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Get policy details" INFO
            $getPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader

            $getPolicyDetails.Policy.Name = $policy.PolicyName -replace "^\[IMPORTED\]", ""
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Renamed as $($getPolicyDetails.Policy.Name)" INFO

            $updatePolicyJson = $getPolicyDetails.Policy | ConvertTo-Json -Depth 10
 
            $updatePolicy = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($policy.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body ([System.Text.Encoding]::UTF8.GetBytes($updatePolicyJson)) # to handle special char
            Write-Log "$counter/$($policySearch.FilteredCount) - $($policy.PolicyName): Policy updated succesfully. Policy name is: $($updatePolicy.Name)" INFO
            $counter++
        }
    }
}
