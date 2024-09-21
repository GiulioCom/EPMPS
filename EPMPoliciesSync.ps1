<#
.SYNOPSIS
    

.DESCRIPTION
Demo Script for sync policies and application group between a master SET to all the other SET in the same tenant 

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMPoliciesSync.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 1
    Created: 09/2024
    Last Modified: 09/2024
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

 #   [Parameter(HelpMessage="Please enter valid EPM set name")]
 #   [string]$setName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [switch]$monitor,
    [string]$addToNewSet
)

### Global Variable ###
### List of Master Policies and Application Group
$masterPolicies = (
    "Master Policy"
)

$masterAppGroups = (
    "Master AppGroup"
)

$masterSetID = "b0f91d72-c448-4e88-ab6a-cfef6b456616" # [Giulio] Monitor(cyberark_16)


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

# Base Function to connet with EPM Console
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

function Save-AdvAgentConf {
    param (
        [string]$managerURL,
        [string]$setID,
        [string]$setName,
        [hashtable]$sessionHeader,
        [string]$folder
    )

    Write-Log "Getting Advanced Agent General Configuration" INFO
    # Policy never stored. Retrieve the policy details
    $getPolicyObj = Invoke-EPMRestMethod -Uri "$managerURL/EPM/API/Sets/$setID/Policies/AgentConfiguration/Default" -Method 'GET' -Headers $sessionHeader

    # Destination File Name
    $policyFileName = "$($setName)_$($getPolicyObj.Name).json" -replace "\[|\]|:"
    $policyPath = "$($folder)\$($policyFileName)"

    # Store policy in JSON file
    $getPolicyObj | ConvertTo-Json -Depth 10 | Set-Content -Path $policyPath -Force
    Write-Log "$($getPolicyObj.Name) saved to $($policyPath)" INFO
}

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

if ($null -ne $addToNewSet -and $addToNewSet.Trim() -ne "") {
    
    # Define destination AppGroup name mapping and store the uploaded AppGroup name and ID needed to map policies to appgroupto. Reduce the number of restapi request
    $destAppGroupMap = @{}

    # Get destination SET ID
    $destSETID = (Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $addToNewSet).SetId
    # To Do: Check if the Set is valid.
    Write-Log "Configure Master Policies in $addToNewSet SET ID $destSETID" INFO
    
    # Get Application Groups
    $appGroupsFilter = @{
        "filter" = "PolicyGroupType EQ 8" # Application Group -> Custom Application Group
    }  | ConvertTo-Json
    $appGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
    
    # Get Policies
    $policiesFilter = @{
        "filter" = "PolicyGroupType EQ 3" # Application -> Groups: Advanced, Predefined Policy, Trust
    }  | ConvertTo-Json    
    $policiesList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policiesFilter
    
    # Retrieve and upload Application Groups
    # Search the Master App Group from the Master SET ID
    Write-Box "Processing App Control"
    foreach ($appGroup in $appGroupList.Policies) {
        if ($masterAppGroups -contains $appGroup.PolicyName) {
            # Get Application Group Details
            Write-Log "Get $($appGroup.PolicyName)" INFO
            $retrievedAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/ApplicationGroups/$($appGroup.PolicyId)" -Method 'GET' -Headers $sessionHeader

            # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
            $retrievedAppGroupDetails.Policy.PSObject.Properties.Remove("Id")

            #Convert as JSON ready to be uploaded
            $JSONAppGroupDetails = $retrievedAppGroupDetails.Policy | ConvertTo-Json -Depth 10
            #$JSONAppGroupDetails
            # Upload Application Group Details
            Write-Log "Upload $($appGroup.PolicyName)" INFO
            $uploadAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$destSETID/Policies/ApplicationGroups" -Method 'POST' -Headers $sessionHeader -Body $JSONAppGroupDetails

            # Store app id for future reference whan processin the policies
            #$destAppGroupMap[$uploadAppGroupDetails.Id] = $uploadAppGroupDetails.Name
            $destAppGroupMap[$uploadAppGroupDetails.Name] = $uploadAppGroupDetails.Id
            $destAppGroupMap
            
        } else {
            Write-Log "$($appGroup.PolicyName) is not in $masterAppGroups" WARN
        }
    }
    Write-Box "Done App Control"

    # Retrieve and upload Policies
    Write-Box "Processing Policies"
    foreach ($policy in $policiesList.Policies) {
        if ($masterPolicies -contains $policy.PolicyName) {
            # Get Policy Details
            Write-Log "Get $($policy.PolicyName)" INFO
            $retrievedPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/Server/$($policy.PolicyId)" -Method 'GET' -Headers $sessionHeader
            
            # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
            $retrievedPolicyDetails.Policy.PSObject.Properties.Remove("Id")
            
            # Search if the policy contains an application Group. If yes, the application group detail defined in the policy must be updated with the new value assigned during the Applicaiton Group creation in the previous phase
            for ($i = 0; $i -lt $retrievedPolicyDetails.Policy.Applications.Count; $i++) {
                
                if ($retrievedPolicyDetails.Policy.Applications[$i].applicationType -eq 2) {
                    # Write-Log "Current Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                    
                    # Check if the application group ID is available in the Application Group mapping
                    if ($destAppGroupMap.ContainsKey($retrievedPolicyDetails.Policy.Applications[$i].displayName)) {
                        # Update the application's id with the found key from the destination map
                        $retrievedPolicyDetails.Policy.Applications[$i].id = $destAppGroupMap[$retrievedPolicyDetails.Policy.Applications[$i].displayName]
                        # Write-Log "New Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                    } else {
                        Write-Log "Value '$($retrievedPolicyDetails.Policy.Applications[$i].applicationType)' not found in the hashtable." ERROR
                    }
                } else {
                    # Write-Log "In index $i applicationType value is $($retrievedPolicyDetails.Policy.Applications[$i].applicationType)" WARN
                }
            }
            
            #Convert as JSON ready to be uploaded
            $JSONPolicyDetails = $retrievedPolicyDetails.Policy | ConvertTo-Json -Depth 10
            
            # Upload Application Group Details
            Write-Log "Upload $($policy.PolicyName)" INFO
            $uploadPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$destSETID/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $JSONPolicyDetails
        } else {
            # Write-Log "$($policy.PolicyName) is not in $masterPolicies" WARN
        }
    }
    Write-Box "Done Policies"

    # Retrieve and upload Agent Conf
    Write-Box "Agent Configuration"
    $getAgentConfs = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/AgentConfiguration/Search" -Method 'POST' -Headers $sessionHeader
    
    foreach ($agentConf in $getAgentConfs.Policies) {
        if ($agentConf.PolicyName -eq "General configuration")
        $getGeneralAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/AgentConfiguration/$($agentConf.PolicyId)" -Method 'POST' -Headers $sessionHeader
        $getGeneralAgentConf.Policy.Id = $destSETID
        $JSONGeneralAgentConf = $getGeneralAgentConf.Policy | ConvertTo-Json -Depth 10
        $updateGeneralAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$destSETID/Policies/AgentConfiguration/$destSETID" -Method 'PUT' -Headers $sessionHeader -Body $JSONGeneralAgentConf
    }
    
    


# Export Policies, App Group and Adv Config
#Save-PolicyOrAppGroup -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -objectType "Server" -sessionHeader $sessionHeader -folder $destinationFolder
#Save-PolicyOrAppGroup -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -objectType "ApplicationGroups" -sessionHeader $sessionHeader -folder $destinationFolder
#Save-AdvAgentConf -managerURL $($login.managerURL) -setID $($set.setId) -setName $($set.setName) -sessionHeader $sessionHeader -folder $destinationFolder


}