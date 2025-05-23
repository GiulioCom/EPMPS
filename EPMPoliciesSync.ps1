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
    "MasterPolicy"
)

$masterAppGroups = (
    "MasterAppGroup"
)

$masterSetID = "893e4fa4-0b60-4e11-a939-04a8d5893bb9" # [Giulio] Monitor(cyberark_16)


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

function Get-PolicyName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$inputString
    )
    
    # Define the regular expression to extract the content between quotes
    $regex = '.*"(.*?)".*'

    # Use [regex]::Match() to find the quoted content in the string
    $match = [regex]::Match($inputString, $regex)

    # If a match is found, return the captured text; otherwise, return null
    if ($match.Success) {
        return $match.Groups[1].Value
    } else {
        return $null
    }
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
    Write-Box "Application Groups"
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
    Write-Box "Application Groups - Done"

    # Retrieve and upload Policies
    Write-Box "Policies"
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
    Write-Box "Policies - Done"

<#    
    # Retrieve and upload Agent Conf
    Write-Box "Agent Configuration"
    $getAgentConfs = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/AgentConfiguration/Search" -Method 'POST' -Headers $sessionHeader
    
    foreach ($agentConf in $getAgentConfs.Policies) {
        if ($agentConf.PolicyName -eq "General configuration") {
            $getGeneralAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/AgentConfiguration/$($agentConf.PolicyId)" -Method 'POST' -Headers $sessionHeader
            $getGeneralAgentConf.Policy.Id = $destSETID
            $JSONGeneralAgentConf = $getGeneralAgentConf.Policy | ConvertTo-Json -Depth 10
            $updateGeneralAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$destSETID/Policies/AgentConfiguration/$destSETID" -Method 'PUT' -Headers $sessionHeader -Body $JSONGeneralAgentConf
        } else {
            # Write-Log ($($agentConf.PolicyName) is not a General Configuration)
        }
    }
    Write-Box "Agent Configuration - Done"
#>
} elseif ($monitor) {
    while ($true){
        # Scan event on each SET
        $sets = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets" -Method 'GET' -Headers $sessionHeader
        foreach ($set in $sets.Sets){
            Write-Log $set.Name INFO
            #if ($set.Id -ne $masterSetID){
            if ($set.Name -eq "[Giulio] QuickStart(cyberark_16)"){
                Write-Box "Checking $($set.Name) - $($set.Id)"
                
                $MasterAppGroupDetails = ""
                $MasterPolicyDetails = ""
                $eventsNumber = 0
                $lastEventTime
                $destinationFolder = [System.IO.Path]::GetTempPath()
                
                # Prepare destination Folder used to store Last Events Time analyzed
                # Sanitize SET name, could contain charater not allowed
                $sanitizedSetName = $set.Name -replace ('\[|\]|\/', '')
                $filename = "EPMPolicySync_$($sanitizedSetName)_lastAuditEvent.txt"
                $lastProcessedEventFile = Join-Path -Path $destinationFolder -ChildPath $filename

                # Create Folder
                try {
                    New-Item -ItemType Directory -Path $destinationFolder -Force -ErrorAction Stop | Out-Null
                } catch {
                    # Handle errors if necessary
                    Write-Log "Error creating directory: $_." -severity ERROR -ForegroundColor Red
                }

                # Check if the file exists
                try {
                    if (!(Test-Path -Path $lastProcessedEventFile -PathType Leaf)) {
                        # If the file does not exist, continue with the rest of the code
                        Write-Log "The $filename file does not exist in the folder." -severity WARN -ForegroundColor Yellow
                    } else {
                        #If exist take the date info
                        $lastEventTime = Get-Content -Path $lastProcessedEventFile -TotalCount 1
                    }
                } catch {
                    # Handle errors if necessary
                    Write-Log "Error loading $filename." -severity ERROR -ForegroundColor Red
                }

                if ([string]::IsNullOrWhiteSpace($lastEventTime)) {
                    $URLParm = "Limit=500"
                } else {
                    $URLParm = "DateFrom=$lastEventTime&Limit=500"
                }

                $setAdminsAudits = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.Id)/AdminAudit?$URLParm" -Method 'GET' -Headers $sessionHeader

                # Order events by EventTime
                $setAdminsAuditsSortByEventTime = $setAdminsAudits.AdminAudits | Sort-Object -Property EventTime
        
                Write-Log "Searching for Audit Events..." -severity INFO -ForegroundColor DarkCyan
                foreach ($setAdminsAudit in $setAdminsAuditsSortByEventTime) {
                    # Search for Events related to Master Policy
                    if ($setAdminsAudit.Description -match [regex]::Escape($masterAppGroups)){
                        if ($setAdminsAudit.PermissionDescription -eq "Change Policy"){
                            if ($setAdminsAudit.Feature -eq "Application Groups"){
                                Write-Log "$($setAdminsAudit.Description)"
                                # Extract the app group name 
                                $modAppGroupName = Get-PolicyName -inputString $setAdminsAudit.Description

                                if ($null -eq $modAppGroupName) {
                                    Write-Log "Error extracting policy name from event" ERROR
                                    break
                                }

                                # Get the modified app group Id
                                $appGroupsFilter = @{
                                    "filter" = "PolicyName CONTAINS ""$modAppGroupName""" # Search the application group modified
                                }  | ConvertTo-Json
                                $modAppGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.Id)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter
                                Write-Log "Modified $($modAppGroupList.Policies.PolicyName) - $($modAppGroupList.Policies.PolicyId)" INFO
                                
                                # Get the Application Group from the Master SET only the first time to reduce the EPM request
                                if ($MasterAppGroupDetails -eq "") {
                                    # Get Application Groups from the Master Set, filtered by the modified Application Group
                                    $masterAppGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter

                                    # Get Application Group Details
                                    $MasterAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/ApplicationGroups/$($masterAppGroupList.Policies.PolicyId)" -Method 'GET' -Headers $sessionHeader
                                }

                                # Copy the Master App Group Details
                                $uploadAppGroupDetails = $MasterAppGroupDetails
                                
                                # Replace Master App Group Id with the current one
                                $uploadAppGroupDetails.Policy.Id = $modAppGroupList.Policies.PolicyId
                                $JSONuploadAppGroupDetails = $uploadAppGroupDetails.Policy | ConvertTo-Json -Depth 10

                                # Update App Group Modified
                                $UpdateAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.Id)/Policies/ApplicationGroups/$($uploadAppGroupDetails.Policy.Id)" -Method 'PUT' -Headers $sessionHeader -Body $JSONuploadAppGroupDetails
                                $eventsNumber++

                            } elseif ($setAdminsAudit.Feature -eq "Policies"){
                                Write-Log "$($setAdminsAudit.Description)"
                                
                                $appId = "" # Store application group ID if present in the policy

                                $modPolicyName = Get-PolicyName -inputString $setAdminsAudit.Description

                                if ($null -eq $modPolicyName) {
                                    Write-Log "Error extracting policy name from event" ERROR
                                    break
                                }
                                
                                # Get the modified policy group Id
                                $policyFilter = @{
                                    "filter" = "PolicyName CONTAINS ""$modPolicyName""" # Search the application group modified
                                }  | ConvertTo-Json
                                $modPolicyList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.Id)/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $policyFilter
                                Write-Log "Modified $($modPolicyList.Policies.PolicyName) - $($modPolicyList.Policies.PolicyId)" INFO

                                # Get modified policy details
                                $modPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.Id)/Policies/Server/$($modPolicyList.Policies.PolicyId)" -Method 'GET' -Headers $sessionHeader
                                # Search if the policy contains an application Group. If yes, the application group ID referred in the policy must be saved to be replaced from the Master Policy
                                for ($i = 0; $i -lt $modPolicyDetails.Policy.Applications.Count; $i++) {
                                    
                                    if ($modPolicyDetails.Policy.Applications[$i].applicationType -eq 2) {
                                        # Write-Log "Current Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                                        $appId = $modPolicyDetails.Policy.Applications[$i].id
                                    } else {
                                        Write-Log "No Appliction Group in this policy"
                                    }
                                }
                                
                                # Get the Policy from the Master SET only the first time to reduce the EPM request
                                if ($MasterPolicyDetails -eq "") {

                                    $policyFilter = @{
                                        "filter" = "PolicyName CONTAINS ""$modPolicyName""" # Search the application group modified
                                    }  | ConvertTo-Json
                                    # Get Application Groups from the Master Set, filtered by the modified Application Group
                                    $masterPolicyList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/Server/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter

                                    # Get Application Group Details
                                    $MasterPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$masterSetID/Policies/Server/$($masterPolicyList.Policies.PolicyId)" -Method 'GET' -Headers $sessionHeader
                                }                                

                                # Copy the Master Policy Details
                                $uploadPolicyDetails = $MasterPolicyDetails
                                
                                # Replace Master Policy Id with the current one
                                $uploadPolicyDetails.Policy.Id = $modPolicyList.Policies.PolicyId
                                
                                # Update the app group ID in the policy according to the previous value
                                if ($null -ne $appId) {
                                    for ($i = 0; $i -lt $uploadPolicyDetails.Policy.Applications.Count; $i++) {
                                    
                                        if ($modPolicyDetails.Policy.Applications[$i].applicationType -eq 2) {
                                            # Write-Log "Current Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                                            $uploadPolicyDetails.Policy.Applications[$i].id = $appId
                                        } else {
                                            Write-Log "No Application Group in this policy"
                                        }
                                    }
                                }
                                
                                $JSONuploadPolicyDetails = $uploadPolicyDetails.Policy | ConvertTo-Json -Depth 10

                                # Update App Group Modified
                                $UpdatePolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.Id)/Policies/ApplicationGroups/$($uploadPolicyDetails.Policy.Id)" -Method 'PUT' -Headers $sessionHeader -Body $JSONuploadPolicyDetails
                                $eventsNumber++
                            }
                        
                        } elseif ($setAdminsAudit.PermissionDescription -eq "Delete policy and application group"){
                            if ($setAdminsAudit.Feature -eq "Application Groups"){
                                # To be Checked
                                Write-Log "$($setAdminsAudit.Description)"
                                $eventsNumber++
                            } elseif ($setAdminsAudit.Feature -eq "Policies"){
                                #To be checked
                                Write-Log "$($setAdminsAudit.Description)"
                                $eventsNumber++
                            }                    
                        } else {
                           Write-Log "$($setAdminsAudit.PermissionDescription) is not change or delete" WARN 
                        }
                    } else {
                        Write-Log "$($setAdminsAudit.Description) is not in $masterAppGroups" WARN
                    }
                    
                <#    
                    if ($setAdminsAudit.Feature -eq "Application Groups" -and $setAdminsAudit.PermissionDescription -eq "Change Policy" -and $setAdminsAudit.Description -contains $masterAppGroups) {
                        # Upload the Master Policy modified
                        Write-Log "Modified $($setAdminsAudit.Description)"
                    } elseif ($setAdminsAudit.Feature -eq "Application Groups" -and $setAdminsAudit.PermissionDescription -eq "Change Policy" -and $setAdminsAudit.Description -contains $masterAppGroups) {
                        # Upload the Master AppGroup Policy modified
                        # Search inside the policies that use this
                        # Update the Policy
                        Write-Log "Deleted $($setAdminsAudit.Description)"
                    }
                #>
                <#   
                    if ($setAdminsAudit.PermissionDescription -eq "Create Policy" -or $setAdminsAudit.PermissionDescription -eq "Change Policy") {
                        $pattern = '.*\"(.*?)\".*'
                        if ($setAdminsAudit.Description -match $pattern) {
                            $policyName = $Matches[1]
                            $eventsNumber++
                            Write-Log "$eventsNumber. $($setAdminsAudit.Feature): $policyName" -severity INFO -ForegroundColor DarkCyan
                            
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
                            Write-Log "No match found for $($setAdminsAudit.Description)." -severity WARN -ForegroundColor Yellow
                        }
                    }#>

                    # Update last event time
                    $lastEventTime = $setAdminsAudit.EventTime
                }      

                # Provide events results
                if ($eventsNumber -eq 0) {
                    Write-Box "No event processed"
                } else {
                    Write-Box "Processed $eventsNumber events"
                }

                # Write the value of $lastEventTime to the lastProcessedEvent.txt file
                try {
                    $lastEventTime | Set-Content -Path $lastProcessedEventFile -Encoding UTF8 -ErrorAction Stop
                    Write-Log "Successfully wrote last event time to $lastProcessedEventFile" -severity INFO -ForegroundColor Gray
                } catch {
                    Write-Log "Error writing to $lastProcessedEventFile" -severity ERROR -ForegroundColor Red
                }
            }
            
            #Start-Sleep -Seconds 10
        }

        # Wait for 2 minutes before starting the next scan
        Write-Box "Waiting for 90 sec before next scan..."
        Start-Sleep -Seconds 90

            # Search for the Master Policy Change \ Delete
            # If Policy Change -> Update from Master Policy
            # - Consider the AppGroup Id 
            # If Policy Delete -> Create from Master Policy
            # - Consider the AppGroup Id
            # If Application Group Change -> Update from Master Policy
            # If Application Group Delete -> Create from Master Policy 
            # - Consider updating the policy app Group reference
    }
}

