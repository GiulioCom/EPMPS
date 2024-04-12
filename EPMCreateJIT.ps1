<#
.SYNOPSIS
    Create JIT (Just-in-Time) policies based on manual request events.

.DESCRIPTION
    1. Retrieve events from EPM that occurred after the last stored timestamp.
    2. Create JIT policies in EPM based on the retrieved events.
    3. Update the log file with the latest event timestamp.

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.NOTES
    File: EPMCreateJIT.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.2 - POC
    Date: 01/2024
    
.EXAMPLE
    .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu"
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [string]$tenant
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

    $apiDelaySeconds = 120  # Too many calls per 2 minute(s). The limit is 10
    $maxRetries = 3         # Maximum number of retry attempts in case of rate limiting or other transient issues.
    $retryCount = 0         # Initialize the retry counter.

    while ($retryCount -lt $maxRetries) {
        try {
            # Invoke the REST API using the specified parameters
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            
            # If successful, return the API response
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

            # # Check for specific rate-limiting error: EPM00000AE - Too many calls per 2 minute(s). The limit is 10
            if ( $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                Write-Host $ErrorDetailsMessage.ErrorMessage
                Write-Host "Retrying in $apiDelaySeconds seconds..."
                Start-Sleep -Seconds $apiDelaySeconds
                $retryCount++
            }
            else {
                # If a different error occurs, re-throw the exception with detailed information.
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

# Set the last events, by default 1 month
$lastEventTimestamp = (Get-Date).AddMonths(-1).ToString('yyyy-MM-ddTHH:mm:ss.ffZ')

# Get the directory where the script is located
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Combine the script directory with the filename
$logFile = Join-Path $scriptDirectory "lastEvents.txt"

# Check if the file exists
if (Test-Path $logFile -PathType Leaf) {
    # Read the first line from the file
    $firstLine = Get-Content $logFile -First 1

    # Define a regex pattern for the timestamp format "2024-01-12T16:51:32.303Z"
    $timestampPattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'

    # Check if the first line matches the timestamp pattern
    if ($firstLine -match $timestampPattern) {
        # Assign the timestamp to a variable
        $lastEventTimestamp = $matches[0]

        # Display the timestamp
        Write-Host "Searching Manual Request events from $lastEventTimestamp"
    }
    else {
        Write-Host "The first line does not match the expected timestamp format. Starting the event search from $lastEventTimestamp"
    }
} 
else {
    Write-Host "The file does not exist. Starting the event search from $lastEventTimestamp"
}

# Get Events
$eventsFilter = @{
    "filter" = "eventDate GE $lastEventTimestamp AND eventType IN ManualRequest"
}  | ConvertTo-Json

$events = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Events/Search?limit=1000" -Method 'POST' -Headers $sessionHeader -Body $eventsFilter

foreach ($event in $events.events) {

    # Create JIT policy
    Write-Host "Create JIT policy for $($event.userName) on $($event.computerName)"
    
    $policyDetails = @{
        "Name" = "JIT $($event.userName) on $($event.computerName)"
        "IsActive" = $true
        "IsAppliedToAllComputers" = $false
        "PolicyType" = 40
        "Action" = 20
        "Duration" = "1"
        "KillRunningApps" = $true
        "Audit" = $true
        "Executors" = @(
            @{
                "Id" = "$($event.agentId)"
                "Name" = "$($event.computerName)"
                "ExecutorType" = 1
            }
        )
        "Accounts" = @(
            @{
                "SamName" = "$($event.userName)"
                "DisplayName" = "$($event.userName)"
                "AccountType" = 1
            }
        )
        "IncludeADComputerGroups" = @()
        "TargetLocalGroups" = @(
            @{
                "AccountType" = 0
                "DisplayName" = "Administrators"
            }
        )
    }  | ConvertTo-Json

    Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $policyDetails


    # Update last event timestamp in the log file
    $event.arrivalTime | Set-Content -Path $logFile -Force

}
