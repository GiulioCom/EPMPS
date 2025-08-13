<#
.SYNOPSIS
    Import policies file, by reading the JSON file in a folder

.DESCRIPTION
    
.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1 - INTERNAL
    Date: 08/2025

.EXAMPLE
    # Define the Set Name
    .\EPMPoliciesImport.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -policiesfolder "c:\EPMbackup"
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

    [Parameter(Mandatory = $true)]
    [string]$policiesfolder
)

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
        [int]$RetryDelay = 120
    )

    $retryCount = 0

    while ($retryCount -lt $MaxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Body $Body -Headers $Headers -ErrorAction Stop
            return $response
        }
        catch {
            #$errorMessage = $_.Exception.Message
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
            
            if ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM00000AE") {
                # Handle rate limit error (EPM00000AE)
                Write-Log "$($ErrorDetailsMessage.ErrorMessage) - Retrying in $RetryDelay seconds..." WARN
                Start-Sleep -Seconds $RetryDelay
                $retryCount++
            } elseif ($ErrorDetailsMessage -and $ErrorDetailsMessage.ErrorCode -eq "EPM000002E"){
                # Handle Error while upload a policy.
                Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                
                # Return a custom object with error info and a flag to indicate failure.
                return [PSCustomObject]@{
                    Success = $false
                    ErrorCode = $ErrorDetailsMessage.ErrorCode
                    ErrorMessage = $ErrorDetailsMessage.ErrorMessage
                }
            } else {
                Write-Log "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)" ERROR
                # Thow the Blocking error
                throw "API call failed at line $($MyInvocation.ScriptLineNumber) - ErrorCode: $($ErrorDetailsMessage.ErrorCode), ErrorMessage: $($ErrorDetailsMessage.ErrorMessage)"
            }
        }
    }

    # If all retries fail, log and throw an error
    if ($retryCount -eq $MaxRetries) {
        Write-Log "API call failed after $MaxRetries retries. URI: $URI" ERROR
        throw "API call failed after $MaxRetries retries."
    }
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

function Process-ExecutorsArray {
    param (
        [Parameter(Mandatory = $true)]
        [array]$ExecutorsArray
    )

    $executorTypeMap = @{
        0 = "Computer Group"
        1 = "Single Computer"
    }
    
    # Iterate through each object in the array and print the "Name" property
    foreach ($executor in $ExecutorsArray) {    
        if ($executor.IsIncluded -eq $true) { 
            Write-Log "$($executorTypeMap[$executor.ExecutorType]) - Name: $($executor.Name) - Included in the Policy" INFO
        } else {
            Write-Log "$($executorTypeMap[$executor.ExecutorType]) - Name: $($executor.Name) - Excluded from Policy" INFO
        }
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
##

Write-Box "$scriptName"
##

# Request EPM Credentials
$credential = Get-Credential -UserName $username -Message "Enter password for $username"

# Authenticate
$login = Connect-EPM -credential $credential -epmTenant $tenant

# Create a session header with the authorization token
$sessionHeader = @{
    "Authorization" = "basic $($login.auth)"
    "Content-Type" = "application/json"
    "charset"="utf-8"
}

Write-Log "Select the Destination SET" INFO

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

Write-Box "$($set.setName)"

Write-Log "Reading files from folder $policiesfolder" INFO

# Check if the backup folder exists
if (-not (Test-Path $policiesfolder)) {
    Write-Log "$($policiesfolder) not exist. Exit" ERROR
    exit
}

# Check if the folder contains any .json files
$policiesFile = Get-ChildItem -Path $policiesfolder -Filter *.json -File
if ($policiesFile.Count -eq 0) {
    Write-Log "The folder '$policiesfolder' does not contain any .json files." ERROR
    exit
} else {
    Write-Log "Found $($policiesFile.Count) JSON file(s) in '$PoliciesFolder'." INFO
    Write-Log "Starting processing JSON files..." INFO
}

# Group files by type of policy, e.g., "Application Group"
$applicationGroupFiles = @()
$advPolicyFiles = @()
$otherPolicyFile = @()

foreach ($file in $policiesFile) {

    try {
        # Read the content of the JSON file as a single string (-Raw)
        # and convert it from JSON format to a PowerShell object.
        $content = Get-Content -Path $file.FullName -Encoding UTF8 -Raw | ConvertFrom-Json

        # Check if the 'PolicyType' property exists and its value is and Application Group (Windows, Linux, macOS).
        if ($content.PolicyType -eq 14 -or
            $content.PolicyType -eq 15 -or
            $content.PolicyType -eq 16) {
            $applicationGroupFiles += $file 
        } elseif ($content.PolicyType -eq 11 -or
            $content.PolicyType -eq 12 -or
            $content.PolicyType -eq 13) {
            $advPolicyFiles += $file 
        } elseif ($content.PolicyType -is [int]){
            $otherPolicyFile += $file
        } else {
            Write-Log "'$($file.FullName)' is not a valid EPM policy file" ERROR
            Continue
        }

    } catch {
        # Catch and report any errors that occur during file reading or JSON parsing.
        Write-Log "ERROR: Could not process file '$($file.Name)'. Details: $($_.Exception.Message)" ERROR
    }
}

# Define destination AppGroup name mapping to store the uploaded AppGroup name and new ID needed to map policies with EPM policy.
# Reduce the number of restapi request
$destAppGroupMap = @{}

# Process files type "Application Group"
if ($applicationGroupFiles.Count -gt 0) {

    $appGroupCounter = 0
    $appGroupSuccessCounter = 0

    Write-Box "Import Application Group"
    Write-Log "Application Groups to be imported: $($applicationGroupFiles.Count)" INFO
    
    foreach ($file in $applicationGroupFiles) {
        $appGroupCounter++
        Write-Log "$appGroupCounter / $($applicationGroupFiles.Count) - Processing 'Application Group' file: $($file.Name)" INFO

        $appGroupDetails = Get-Content -Path $file.FullName -Encoding UTF8 -Raw | ConvertFrom-Json

        # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
        if ($appGroupDetails.PSObject.Properties.Match('Id')) {
            $appGroupDetails.PSObject.Properties.Remove("Id")
        }
        
        $JSONAppGroupDetails = [System.Text.Encoding]::UTF8.GetBytes(($appGroupDetails | ConvertTo-Json -Depth 10 -Compress))

        # Upload Application Group Details
        Write-Log "> Uploading '$($appGroupDetails.Name)'" -ForegroundColor Blue INFO
        $uploadAppGroupDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups" -Method 'POST' -Headers $sessionHeader -Body $JSONAppGroupDetails
        # Check for any non-blocking error
        if ($uploadAppGroupDetails.Success -eq $false) {
            Write-Log "> Error Uploading '$($appGroupDetails.Name)'" ERROR
        } else {
            Write-Log "> Uploaded correcly '$($appGroupDetails.Name)'" INFO
            # Store app id for future reference whan processin the policies
            $destAppGroupMap[$uploadAppGroupDetails.Name] = $uploadAppGroupDetails.Id
            # Increment the couunter of successed
            $appGroupSuccessCounter++
        }
    }
    
    $appGroupFailedCounter = $applicationGroupFiles.Count - $appGroupSuccessCounter
    Write-Log "Application Group Imported: '$appGroupSuccessCounter / $($applicationGroupFiles.Count)'" INFO
    if ($appGroupFailedCounter -gt 0) {
        Write-Log "Application Group not Imported: '$appGroupFailedCounter / $($applicationGroupFiles.Count)'. Please che the log for any error" ERROR
    }
} else {
    Write-Log "Application Group JOSN files not found." WARN
}

<#
# Process files type "Advanced Policies"
if ($advPolicyFiles.Count -gt 0) {

    $advPolicyCounter = 0

    Write-Box "Restoring Advanced Policies"
    Write-Log "Advanced policy to be uploaded: $($advPolicyFiles.Count)" INFO
    
    foreach ($file in $advPolicyFiles) {
        $advPolicyCounter++
        Write-Log "$advPolicyCounter/$($advPolicyFiles.Count) - Processing 'Advanced Policy' file: $($file.Name)" INFO
        
        $policyDetails = Get-Content -Path $file.FullName | ConvertFrom-Json
        
        # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
        $policyDetails.PSObject.Properties.Remove("Id")
        
        # Check if the policy contains an application Group.
        # If true, the application group detail defined must be updated with the new Application ID created while restoring App Group
        for ($i = 0; $i -lt $policyDetails.Applications.Count; $i++) {
            
            if ($policyDetails.Applications[$i].applicationType -eq 2) {
                # Write-Log "Current Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                
                # Check if the application group ID is available in the Application Group mapping
                if ($destAppGroupMap.ContainsKey($policyDetails.Applications[$i].displayName)) {
                    # Update the application's id with the found key from the destination map
                    $policyDetails.Applications[$i].id = $destAppGroupMap[$policyDetails.Applications[$i].displayName]
                    # Write-Log "New Application ID: $($retrievedPolicyDetails.Policy.Applications[$i].id)" INFO
                } else {
                    Write-Log "Value '$($policyDetails.Policy.Applications[$i].applicationType)' not found in the hashtable." ERROR
                }
            } else {
                # Write-Log "In index $i applicationType value is $($retrievedPolicyDetails.Policy.Applications[$i].applicationType)" WARN
            }
        }

        # Check if the policy is applied to computers (or computer groups)
        if ($policyDetails.Executors.Count -gt 0) {
            # List the compputer applied
            Process-ExecutorsArray -ExecutorsArray $policyDetails.Executors
            # Reset the computer array
            $policyDetails.Executors = @()
            # Set the policy applied to all computers
            $policyDetails.IsAppliedToAllComputers = $true
        }
        
        #Convert as JSON ready to be uploaded
        $JSONPolicyDetails = $policyDetails | ConvertTo-Json -Depth 10
        
        # Upload Application Group Details
        Write-Log "Uploading $($policyDetails.Name)" INFO
        $uploadPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $JSONPolicyDetails    
    }
    Write-Log "Policies restored: $advPolicyCounter/$($advPolicyFiles.Count)" INFO
}

# Process remainig policies
if ($otherFiles.Count -gt 0) {

    $policyCounter = 0

    # Get Predefined App Group Application Groups
    $appGroupsFilter = @{
        "filter" = "PolicyGroupType EQ 9" # Application Group -> Predefined App Group
    }  | ConvertTo-Json
    $predAppGroupList = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups/Search" -Method 'POST' -Headers $sessionHeader -Body $appGroupsFilter

    Write-Box "Restoring Remainig Policies"
    Write-Log "Remaining policies to be uploaded: $($otherFiles.Count)" INFO

    foreach ($file in $otherFiles) {
        Write-Log "$policyCounter/$($otherFiles.Count) - Processing file: $($file.Name)" INFO
        
        if ($file.Name -match "_INT.*_" -or 
            $file.Name -match "_Ransomware Protection.*_" -or 
            $file.Name -match "_Privilege Management.*_") {
            # Do not process default policies, not supported by EPM RestAPI
            Write-Log "Default policy not supported" WARN
        } elseif ($file.Name -match ".*_Predefined App Groups Win_(Allow|Elevate|Block).json" -or
                  $file.Name -match ".*_Developer Applications_Developer Applications.json") {
            # Do not process predefined Windows policies
            Write-Log "Predefined Windows policy not supported" WARN
        } elseif ($file.Name -match ".*_Predefined App Groups Win_(Allow|Elevate|Block) Application Group.json" -or
                  $file.Name -match ".*_Predefined App Groups Win_Developer Applications Application Group.json" ) {
            # Restore the predefined Application Group
            $appGroupDetails = Get-Content -Path $file.FullName | ConvertFrom-Json
            # Search the current app group ID
            foreach ($preAppGroup in $predAppGroupList.Policies) {
                # Once found it, restore the application group
                if ($predAppGroup.PolicyName -eq $appGroupDetails.Name) {
                    Write-Log "Uploading $($file.Name)" INFO
                    $JSONappGroupDetails = $appGroupDetails | ConvertTo-Json -Depth 10
                    $updatePolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server/$($predAppGroup.PolicyId)" -Method 'PUT' -Headers $sessionHeader -Body $JSONappGroupDetails
                }
            }
        } elseif ($file.Name -match ".*_General configuration.json"){
            # Restore the Agent Configuration
            $policyDetails = Get-Content -Path $file.FullName | ConvertFrom-Json
            $JSONGeneralAgentConf = $policyDetails.Policy | ConvertTo-Json -Depth 10
            $updateGeneralAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration/$($set.setId)" -Method 'PUT' -Headers $sessionHeader -Body $JSONGeneralAgentConf

        } else {
            # Restore the remaining policies (Trust Source, User policies, etc)
            $policyDetails = Get-Content -Path $file.FullName | ConvertFrom-Json
            # Remove the Policy ID to prevent "ErrorMessage: You cannot create policy while providing an Id, Id value must be empty"
            $policyDetails.PSObject.Properties.Remove("Id")
            
            # Check if the policy is applied to computers (or computer groups)
            if ($policyDetails.Executors.Count -gt 0) {
                # List the compputer applied
                Process-ExecutorsArray -ExecutorsArray $policyDetails.Executors
                # Reset the computer array
                $policyDetails.Executors = @()
                # Set the policy applied to all computers
                $policyDetails.IsAppliedToAllComputers = $true
            }
            
            # Convert as JSON ready to be uploaded
            $JSONPolicyDetails = $policyDetails | ConvertTo-Json -Depth 10
            Write-Log "Uploading $($file.Name)" INFO
            $uploadPolicyDetails = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $JSONPolicyDetails    
        }
        $policyCounter++
    }
    Write-Log "Policies restored: $policyCounter/$($otherFiles.Count)" INFO
}
#>

Write-Box "Import Completed"