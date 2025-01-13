<#
.SYNOPSIS
    Duplicate Agent Configuratio, create new agent configuration starting from the an active agent configuration.

.DESCRIPTION
    1. Get the agent configuration used as source.
    2. Copy the configuration for new agent

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
    Version: 0.1 - POC
    Date: 01/2025

.RELEASE NOTES
    01/2025 - Initial Version

.EXAMPLE
    1. .\EPMDuplicateAgentConf.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -agentPolicyName "Ubuntu" -destCompName "Ubuntu2204-1"
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

    [Parameter(Mandatory = $true, HelpMessage = "Please provide the agent configuration policy name used as source for policy settings.")]
    [string]$agentPolicyName,

    [Parameter(Mandatory = $true, HelpMessage = "Please provide the computer name where the policy will apply.")]
    [string]$destCompName
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

function Get-ComputerID {
    param (
        [string] $compName
    )

    $getComputers = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Computers?`$filter=ComputerName eq '$compName'" -Method 'GET' -Headers $sessionHeader
    
    if ($getComputers.Computers.length -eq 0 ) {
        Write-Log "No Computer named $compName was found, please refine your search." ERROR
        exit
    } elseif ($getComputers.Computers.length -gt 1) {
        Write-Log "To many device found having name $compName was found, please refine your search." ERROR
        exit
    } else {
        Write-Log "$compName having ID: $($getComputers.Computers[0].AgentId)" INFO
        return $getComputers.Computers[0].AgentId
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

# Get the agent configuration policy 

$agentConfDetails = ""
$destCompId = ""

Write-Log "Searching from Agent Configuration name: $agentPolicyName" INFO
$agentPolicies = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration/Search" -Method 'POST' -Headers $sessionHeader
foreach ($agentPolicy in $agentPolicies.Policies) {
    if ($agentPolicy.PolicyName -eq $agentPolicyName) {
        $agentConfDetails = Invoke-EPMRestMethod -URI "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration/$($agentPolicy.PolicyId)" -Method 'GET' -Headers $sessionHeader
        $agentConfDetails = $agentConfDetails.Policy
        Write-Log "Agent Configuration name $agentPolicyName found!" INFO
    }
}

if ($agentConfDetails -eq "") {
    Write-Log "Agent Configuration name $agentPolicyName does not exist. Check the policy name!" ERROR
    exit
} else {
    $destCompId = Get-ComputerID -compName $destCompName

    # Remove the ID
    $agentConfDetails.PSObject.Properties.Remove("Id")
    
    # Update Agent ID and Computer Name
    $agentConfDetails.Executors[0].id = $destCompId
    $agentConfDetails.Executors[0].Name = $destCompName
    
    # Update Policy Name
    $agentConfDetails.Name = $destCompName

    #Convert policy as JSON ready to be uploaded
    $JSONagentConfDetails = $agentConfDetails | ConvertTo-Json -Depth 10
    # Upload Application Group Details
    Write-Log "Uploading Agent Configuration for $destCompName..." INFO
    $uploadAgentConf = Invoke-EPMRestMethod -Uri "$($login.managerURL)/EPM/API/Sets/$($set.setId)/Policies/AgentConfiguration" -Method 'POST' -Headers $sessionHeader -Body $JSONagentConfDetails
}    
