<#
.SYNOPSIS
    Massive Upload Application group definition from a CSV

.DESCRIPTION

.PARAMETER username
    The EPM username (e.g., user@domain).

.PARAMETER setName
    The name of the EPM set.

.PARAMETER tenant
    The EPM tenant name (e.g., eu, uk).

.PARAMETER destinationFolder


.NOTES
    File: EPMAppGroupUpload.ps1
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 1
    Created: 08/2024
    Last Modified: 08/2024
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

    [Parameter(HelpMessage = "Specify the csv filename which contain data to import")]
    [string]$csvFile

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


function Add-Application {
    param (
        $applicationDefinition,
        $propertyType,
        $propertyValue
    )

    # Manage Applications
    # Define the Application Type
    if ($propertyType -eq "FileType"){
            switch ($propertyValue) {
                "exe" { $applicationType = 3 }
                Default {}
            }
        $applicationDefinition.applicationType = $applicationType
    }

    # Define the application fileds
    if ($propertyType -eq "FileName") {
        $fileNamePattern = @{
            "@type" = "FileName"
            "hashAlgorithm" = ""
            "hash" = ""
            "hashSHA256" = ""
            "fileSize" = 0
            "isEmpty" = $true
            "content" = $propertyValue
            "compareAs" = 0
            "caseSensitive" = $false
        }
        
        # Add aplication properties
        $applicationDefinition.patterns.Add("FILE_NAME", $fileNamePattern)
    }

    if ($propertyType -eq "Publisher") {
        $publisherPattern =  @{
            "@type" = "Publisher"
            "content" = $propertyValue
            "compareAs" = 0
            "caseSensitive" = $true
            "onlyEmptyValue" = $false
            "isEmpty" = $true
            "signatureLevel" = 2
            "separator" = ";"
        }
        # Add aplication properties
        $applicationDefinition.patterns.Add("PUBLISHER", $publisherPattern)
    }

    if ($propertyType -eq "Path") {
        $locationPattern = @{
            "@type" = "Location"
            "content" = $propertyValue
            "withSubfolders" = $true
            "caseSensitive" = $true
            "isEmpty" = $false
        }
        # Add aplication properties
        $applicationDefinition.patterns.Add("LOCATION", $locationPattern)
    }

    #return $applicationDefinition

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
}

# Get SetId
$set = Get-EPMSetID -managerURL $($login.managerURL) -Headers $sessionHeader -setName $setName

## Load CSV file
# Check if the file exists
if (-not (Test-Path $csvFile)) {
    Write-Log "CSV file not found at path: $csvFile" -severity ERROR
    exit
}

$appGroupNamesTracker = @{}

# Import the CSV file
$csvData = Import-Csv -Path $csvFile
foreach ($row in $csvData) {

    # Create the App Group Object
    $currentAppGroupName = $row.AppGroupName

    # Store column names
    $columnNames = $csvData[0].PSObject.Properties.Name

    # Check if the AppGroupName is already present
    if (-not $appGroupNamesTracker.ContainsKey($currentAppGroupName)) {
        # If not present, create the ApplicationGroup

        $appGroup = @{
            "Applications" = @()
            "PolicyType" = ""
            "Name" = $row.AppGroupName
            "Description" = "App Group created by Script"
        }

        # Manage AppGroup Type
        switch ($row.AppGroupType) {
            "Windows" { $PolicyType = 14 }
            "Linux" { $PolicyType = 15 }
            "MacOS" { $PolicyType = 16 }
            Default {}
        }

        $appGroup.PolicyType = $PolicyType

        # Store the AppGroupName in the hashtable
        $appGroupNamesTracker[$currentAppGroupName] = $appGroup

        # Code to add the first app properties

        # Application Group Template
        $appDefinition = @{
            "id" = "00000000-0000-0000-0000-000000000000"
            "internalId" = 0
            "internalIndex" = 0
            "applicationType" = 0
            "displayName" = ""
            "description" = ""
            "patterns" = @{}
            "applicationGroupId" = "00000000-0000-0000-0000-000000000000"
            "internalApplicationGroupId" = 0
            "includeInMatching" = $true
            "softwareDistributorName" = $null
            "accountId" = "00000000-0000-0000-0000-000000000000"
            "childProcess" = $false
            "LinuxChildProcess" = 2
            "restrictOpenSaveFileDialog" = $false
            "securityTokenId" = "00000000-0000-0000-0000-000000000000"
            "protectInstalledFiles" = $false
            "securityLevel" = "LOW"
        }

        # Loop through each column starting from the 4rd column (index 2) "FileType"
        for ($i = 2; $i -lt $columnNames.Count; $i++) {
        
            # Access the column name
            $columnName = $columnNames[$i]
        
            # Check if the column exists and if it has a non-empty value
            if ($row.PSObject.Properties[$columnName] -and $row.$columnName) {
                # If the column is present and the value is non-empty, execute the function
                Add-Application -applicationDefinition $appDefinition -propertyType $columnName -propertyValue $row.$columnName
            }
        }
        
        $appGroupNamesTracker[$currentAppGroupName]["Applications"] += $appDefinition

    } else {

        # Application Group Template
        $appDefinition = @{
            "id" = "00000000-0000-0000-0000-000000000000"
            "internalId" = 0
            "internalIndex" = 0
            "applicationType" = 0
            "displayName" = ""
            "description" = ""
            "patterns" = @{}
            "applicationGroupId" = "00000000-0000-0000-0000-000000000000"
            "internalApplicationGroupId" = 0
            "includeInMatching" = $true
            "softwareDistributorName" = $null
            "accountId" = "00000000-0000-0000-0000-000000000000"
            "childProcess" = $false
            "LinuxChildProcess" = 2
            "restrictOpenSaveFileDialog" = $false
            "securityTokenId" = "00000000-0000-0000-0000-000000000000"
            "protectInstalledFiles" = $false
            "securityLevel" = "LOW"
        }   

        # Loop through each column starting from the 4rd column (index 2) "FileType"
        for ($i = 2; $i -lt $columnNames.Count; $i++) {

            # Access the column name
            $columnName = $columnNames[$i]
        
            # Check if the column exists and if it has a non-empty value
            if ($row.PSObject.Properties[$columnName] -and $row.$columnName) {
                # If the column is present and the value is non-empty, execute the function
                Add-Application -applicationDefinition $appDefinition -propertyType $columnName -propertyValue $row.$columnName
            }
        }

        $appGroupNamesTracker[$currentAppGroupName]["Applications"] += $appDefinition
    }
}

Write-Log "Created $($appGroupNamesTracker.Count) application groups:" INFO
foreach ($key in $appGroupNamesTracker.Keys) {
    
    Write-Log "Application Group Name: $key" INFO
    
    if ($appGroupNamesTracker[$key] -is [hashtable]) {
        $appGroupJson = $appGroupNamesTracker[$key] | ConvertTo-Json -Depth 10
        # Import Application Group
        $createAppGroup = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/ApplicationGroups" -Method "POST" -Headers $sessionHeader -Body $appGroupJson
        Write-Log $createAppGroup INFO
    }

    Write-Log "-------------------------" INFO
}


