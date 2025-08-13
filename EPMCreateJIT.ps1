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

.RELEASE NOTES
    01/2024 - Initial Version
    12/2024 - Adding Logs
    12/2024 - Improve last date management

.EXAMPLE
    1. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu"
        Check events in the set, no log created, lastEventFile stored in the script current folder \lastEvents
    2. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -log -logFolder "C:\Logs" -lastEventFolder "C:\Events"
        Check events in the set, create log in the custom folder C:\Logs and last event file in C:\Events\
    3. .\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -log -lastEventFolder "C:\Events"
        Check events in the set, create log in the "current script folder\log" and last event file in "C:\Events"
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [string]$username,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [string]$setName = "",

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [ValidateSet("login", "eu", "uk", "au", "ca", "in", "jp", "sg", "it", "ch")]
    [string]$tenant,

    [Parameter(HelpMessage = "Enable logging to file and console")]
    [switch]$log,

    [Parameter(HelpMessage = "Specify the log file path")]
    [string]$logFolder,

    [Parameter(HelpMessage = "Please provide the folder to store the last event date detail.")]
    [string]$lastEventFolder
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

function Resolve-Folder {
    param (
        [string]$ProvidedFolder,
        [string]$DefaultSubFolder
    )

    # Determine the script directory or fallback to current directory
    $scriptDirectory = if ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        Get-Location
    }

    # Use the provided folder or create a default subfolder
    $resolvedFolder = if ($ProvidedFolder) {
        $ProvidedFolder
    } else {
        Join-Path $scriptDirectory $DefaultSubFolder
    }

    # Ensure the folder exists
    if (-not (Test-Path $resolvedFolder)) {
        New-Item -Path $resolvedFolder -ItemType Directory -Force | Out-Null
    }

    return $resolvedFolder
}

function Remove-InvalidCharacters {
    param (
        [Parameter(Mandatory)]
        [string]$InputString
    )

    # Define invalid characters for file names
    $invalidCharacters = '[\\/:*?"<>|[\]]'

    # Remove invalid characters
    $sanitizedString = $InputString -replace $invalidCharacters, ''

    return $sanitizedString
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

function Add-msToTimestamp {
    param (
        [string]$timestamp
    )

    if ($timestamp -match '^(?<Date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?<Milliseconds>\d+))?(?<Zone>Z)$') {
        
        $datePart = $Matches['Date']
        $milliseconds = $Matches['Milliseconds']
        $zone = $Matches['Zone']

        # Ensure milliseconds are always three digits
        $milliseconds = if ($null -eq $milliseconds) { "000" } else { $milliseconds.PadRight(3, '0') }

        $datems = "$datePart.$milliseconds"
        
        # Convert to integer and add 1 millisecond
        $newDate = [datetime]::ParseExact($datems, "yyyy-MM-ddTHH:mm:ss.fff", $null).AddMilliseconds(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        return $newDate
           
    } else {
        throw "Invalid timestamp format: $timestamp"
    }
}

# Logging setup
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
if ($log) {
    $resolvedLogFolder = Resolve-Folder -ProvidedFolder $logFolder -DefaultSubFolder "log"

    # Create log file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "$timestamp`_$scriptName.log"
    $logFilePath = Join-Path $resolvedLogFolder $logFileName

    Write-Log "Logging enabled. Log file: $logFilePath" INFO
}
## Log file done

Write-Box "$scriptName"

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

# Last event tracking setup
$resolvedLastEventFolder = Resolve-Folder -ProvidedFolder $lastEventFolder -DefaultSubFolder "EPMJIT_lastEvents"
# Create or update last event file
$lastEventFile = Join-Path $resolvedLastEventFolder "lastEvents.txt"

# Set the last events, by default 1 month
$lastEventTimestamp = (Get-Date).AddMonths(-1).ToString('yyyy-MM-ddTHH:mm:ss.ffZ')

# Check if the file exists
if (Test-Path $lastEventFile -PathType Leaf) {
    Write-Log "Found last events file: $lastEventFile" INFO
    # Read the first line from the file
    $firstLine = Get-Content $lastEventFile -First 1

    # Define a regex pattern for the timestamp format "2024-01-12T16:51:32.303Z"
    $timestampPattern = '^(?<Date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.)(?<Milliseconds>\d+)(?<Zone>Z)$'

    # Check if the first line matches the timestamp pattern
    if ($firstLine -match $timestampPattern) {
        # Assign the timestamp to a variable
        $lastEventTimestamp = $matches[0]

        # Display the timestamp
        Write-Log "Searching Manual Request events from $lastEventTimestamp" INFO
    } else {
        Write-Log "$firstLine does not match the expected timestamp format. Starting the event search from $lastEventTimestamp" WARN
    }
} else {
    Write-Log "$($lastEventFile): The file does not exist. Starting the event search from $lastEventTimestamp" WARN
}

# Get Events
$eventsFilter = @{
    "filter" = "eventDate GE $lastEventTimestamp AND eventType IN ManualRequest"
}  | ConvertTo-Json

$events = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Events/Search?limit=1000&sortDir=asc" -Method 'POST' -Headers $sessionHeader -Body $eventsFilter

Write-Log $($events | Convertto-Json -Depth 10) INFO

if ($events.filteredCount -gt 0) {
    Write-Log "Found $($events.filteredCount) Manual Request from $lastEventTimestamp" INFO

    foreach ($event in $events.events) {

        # Create JIT policy
        Write-Log "Processing $count of $($events.filteredCount) Manual Request for $($event.userName) on $($event.computerName)" INFO
        
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

        $createJIT = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/Server" -Method 'POST' -Headers $sessionHeader -Body $policyDetails
        if ($createJIT.id) {
            Write-Log "$($createJIT.Name) policy created" INFO
        } else {
            Write-Log "Error creating policy for $($event.userName) on $($event.computerName)" ERROR
        }
        
        # Update lastevents file
        $newfirstEventDate = Add-msToTimestamp -timestamp $event.firstEventDate
        Write-Log "The last event date $($event.firstEventDate), save last event date $newfirstEventDate in $lastEventFile" INFO
        $newfirstEventDate | Set-Content -Path $lastEventFile -Force
    }
} else {
    Write-Log "No new Manual Request from $lastEventTimestamp" INFO
}
