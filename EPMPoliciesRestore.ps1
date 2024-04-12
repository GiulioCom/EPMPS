<#
Note:
- Add Allication Group
- Mapping new app group Id -> olld app Group ID
- Restore Policy
-- If the policy is linked with an application group
--- check from the map the new app group add
--- replace (in memory) the application Id within the policy
--- Complete policy import
#>

param (
    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [Alias("login")]
    [string]$LoginUserName,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [Alias("set")]
    [string]$SetName,

    [Parameter(Mandatory = $true, HelpMessage="Please enter valid EPM tenant (eu, uk, ....)")]
    [Alias("tenant")]
    [string]$TenantServer
)

function restore-AppGroup {
    param (
        [string]$managerURL,
        [string]$setID,
        [string]$setName,
        [hashtable]$sessionHeader
    )

    #$filter = "$($setName)_AppGroup_*.json"
    $filter = 'Pilot(london stock exchange group)_AppGroup_All-Win-Elevate-MFA.json'
    $appGroupFiles = Get-ChildItem -Path "*" -Include $filter
    foreach ($file in $appGroupFiles) {
        
        $policyFile = Get-Content -Path $file -Raw | ConvertFrom-Json
        #$policyFile = Get-Content -Path $file | ConvertFrom-Json
        #$policyFile
        if ($policyFile.Policy.PolicyType -eq 14 -or $policyFile.Policy.PolicyType -eq 15 -or $policyFile.Policy.PolicyType -eq 16) {
            Write-Host "$($policyFile.Policy.Name): preparing data"
            $appGroup = @{
                "Applications" = $policyFile.Policy.Applications
                "PolicyType" = $policyFile.Policy.PolicyType
                "Name" = $policyFile.Policy.Name
                "Description" = $policyFile.Policy.Description
            } | ConvertTo-Json -Depth 10
            $createPolicy = Invoke-RestMethod -Uri "$managerURL/EPM/API/Sets/$setID/Policies/ApplicationGroups" -Method 'POST' -Headers $sessionHeader -Body $appGroup
            $appGroupIdMapping[$policyFile.Policy.Id] = $createPolicy.id
            Write-Host "$($policyFile.Policy.Name): imported"
            Start-Sleep -Seconds $apiDelaySeconds 
        }
    }  
}

$appGroupIdMapping = @{}

# Set the delay between API requests
$apiDelaySeconds = 15

# login server, update if using different server
$loginServer = $TenantServer

# Request EPM Console password
$credential = Get-Credential -UserName $LoginUserName -Message "Enter password for $LoginUserName"

$authBody = @{
    Username = $credential.UserName
    Password = $credential.GetNetworkCredential().Password
    ApplicationID = "Powershell"
} | ConvertTo-Json

$authHeaders = @{
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod -Uri "https://$loginServer.epm.cyberark.com/EPM/API/Auth/EPM/Logon" -Method 'POST' -Headers $authHeaders -Body $authBody
$managerURL = $response.ManagerURL
$auth = $response.EPMAuthenticationResult

$sessionHeader = @{
    "Authorization" = "basic $auth"
    "Content-Type" = "application/json"
}

$sets = Invoke-RestMethod -Uri "https://$loginServer.epm.cyberark.com/EPM/API/Sets" -Method 'GET' -Headers $sessionHeader

$setId = $null
# Check if $SetName is not configured
if ([string]::IsNullOrEmpty($SetName)) {

    # Repeat until a valid set number is entered
    do {
        # List the sets with numbers
        Write-Host "Available Sets:"

        foreach ($i in 0..($sets.Sets.Count - 1)) {
            $set = $sets.Sets[$i]
            Write-Host "$($i + 1). $($set.Name)"
        }
    
        # Ask the user to choose a set by number
        $chosenSetNumber = Read-Host "Enter the number of the set you want to choose"
    
        # Validate the chosen set number
        if ([int]::TryParse($chosenSetNumber, [ref]$null) -and $chosenSetNumber -ge 1 -and $chosenSetNumber -le $sets.Sets.Count) {
            $chosenSet = $sets.Sets[$chosenSetNumber - 1]
            $setId = $chosenSet.Id
            $setName = $chosenSet.Name
        } else {
            Write-Host "Invalid set number."
        }
    } until ($setId)
}

else {
    # List the sets with numbers
    foreach ($set in $sets.Sets) {
        #check if setname match with configured set
        if ($set.Name -eq $SetName) {
            $setId = $set.Id
            break  # Exit the loop once the set is found
        }
    }
    if ([string]::IsNullOrEmpty($setId)) {
        Write-Host "$SetName : Invalid Set"
        exit 1
    }
}

Write-Host "Entering in SET: $setName" -ForegroundColor Yellow

restore-AppGroup -managerURL $managerURL -setID $setID -setName $SetName -sessionHeader $sessionHeader

$appGroupIdMapping