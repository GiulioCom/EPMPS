<#
.SYNOPSIS
    Remove Duplicate Computer Object in EPM Console

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER delete
    Flag to enabled computer deletion

.NOTES
    File: EPMDuplicateComputer.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1
    Created: 04/2024
    Last Modified: 04/2024
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [string]$tenant,

    [Parameter(HelpMessage="Delete duplicated Endpoint")]
    [switch]$delete = $false
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

# Get computers list
$getComputerList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers" -Method 'GET' -Headers $sessionHeader

<#
$getComputerList = @'
[
    {
        "AgentId": "c15764f3-d9ae-4ee0-83e9-f1f5806f91ca",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-14T16:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-11T10:56:35.38",
        "LoggedIn": ""
    },
    {
        "AgentId": "d5f92e1c-bf1b-48f3-9eae-7c5a3e8e642e",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-2",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-15T12:45:09.257",
        "Status": "Connected",
        "LastSeen": "2024-04-11T09:56:35.38",
        "LoggedIn": "user1"
    },
    {
        "AgentId": "e6b14235-2f11-4c8e-bcf2-9e3489776a3c",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-20T08:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-10T10:56:35.37",
        "LoggedIn": ""
    },
    {
        "AgentId": "e6b14234-2f11-4c8e-bcf2-9e3489776a3c",
        "AgentVersion": "24.2.0.1855",
        "ComputerName": "WIN11-1",
        "ComputerType": "Desktop",
        "Platform": "Windows",
        "InstallTime": "2024-03-20T08:27:09.257",
        "Status": "Disconnected",
        "LastSeen": "2024-04-10T10:56:34.37",
        "LoggedIn": ""
    }
]
'@ | ConvertFrom-Json
#>

# Group objects by ComputerName
$groupedComputersByName = $getComputerList | Group-Object -Property ComputerName

# Iterate through each group
foreach ($groupComputer in $groupedComputersByName) {
    # If there are duplicates
    if ($groupComputer.Count -gt 1) {
        # Sort objects in the group by LastSeen in ascending order
        $sorted = $groupComputer.Group | Sort-Object -Property LastSeen -Descending
        $sorted

        # Output the ComputerName and oldest AgentId(s) starting from the array position 1 (order by descending)
        Write-Host "Duplicated ComputerName: $($sorted[0].ComputerName), found $($groupComputer.Count) items"
        for ($i = 1; $i -lt $sorted.Count; $i++) {
            if ($delete) {
                Write-Host "  Deleting $($sorted[$i].AgentId)"    
                Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers/$($sorted[$i].AgentId)" -Method 'DELETE' -Headers $sessionHeader
            } else {
                Write-Host "  $($sorted[$i].AgentId)"
            }

        }
    }
}

