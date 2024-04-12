param (
    [Parameter(HelpMessage="Please enter valid EPM username (For example: user@domain)")]
    [Alias("login")]
    [string]$LoginUserName,

    [Parameter(HelpMessage="Please enter valid EPM set name")]
    [Alias("set")]
    [string]$SetName
)



# Create a temporary folder to extract the contents
$tempFolder = Join-Path -Path $env:TEMP -ChildPath ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempFolder | Out-Null

# Group the policies based on their Policy Type and count the occurrences of each type, also count active\inactive policies
function Get-PolicyTypeCounter {
    param (
        [PSCustomObject]$policyObjects
    )

    $policyTypeGroups = $policyObjects | Group-Object -Property 'Policy Type'
    foreach ($policyType in $policyTypeGroups) {
        Write-Host " - $($policyType.Name): $($policyType.Count)"
        # If policy type is Trust, Advanced, Application check active or not
        if ($policyType.Name -match "(Trust)|(Advanced)|(Application)"){
            $policyActiveGroup = $policyType.Group | Group-Object -Property 'Active'
            $activePolicies = ($policyActiveGroup | Where-Object { $_.Name -eq 'Yes' }).Count
            $inactivePolicies = ($policyActiveGroup | Where-Object { $_.Name -eq 'No' }).Count
            if ($activePolicies -gt 0) {
                Write-Host "   + Active policies: $activePolicies"
            }
            if ($inactivePolicies -gt 0) {
                Write-Host "   + Inactive policies: $inactivePolicies"
            }
        }
    }
}

# Precess Defaulkt Policies and show which is Active\Inactive
function Get-DefaultPolicyTypeStatus {
    param (
        [PSCustomObject]$policyObjects
    )

    foreach ($policyType in $policyObjects) {
        if ($policyType.Active -eq "Yes") {
            Write-Host " - $($policyType.'Policy Type'): Active" -ForegroundColor Green 
        }

        if ($policyType.Active -eq "No") {
            Write-Host " - $($policyType.'Policy Type'): Inactive" -ForegroundColor Red
        }
    }
}

# Search policies based on Audit configuration
function Get-PolicyAudit {

    param (
        [PSCustomObject]$policyObjects
    )    

    foreach ($platform in $policyObjects.Keys) {
        Write-Host "Audit Configuration of $platform Policies" -ForegroundColor DarkGray
        foreach ($policyObject in $policyObjects[$platform]) {
            # Filter only by policy type advanced
            if ($policyObject.'Policy Type' -match '.*Advanced'){
                if ($policyObject.Action -match 'Block|Elevate|Elevate If Necessary'){
                    if ($policyObject.'Collect Policy Usage' -eq 'Never'){
                        Write-Host "$($policyObject.'Policy name'): Audit is currently disabled. To enhance security, we recommned enabling the Audit for policy action $($policyObject.Action)" -ForegroundColor Red
                    }
                }
                if ($policyObject.Action -match 'Allow'){
                    if ($policyObject.'Collect Policy Usage' -ne 'Never'){
                        Write-Host "$($policyObject.'Policy name'): Audit is currently enabled. To improve the policies audit performance, we recommend disabling the Audit for policy action $($policyObject.Action)" -ForegroundColor Red
                    }
                }
            }
        }
        Write-Output "========================"    
    }
}    

# Search for invalid Users configured in policy. A valid user must be in the format domain\username
# Note: in the report the SID detail is missing: 
#       ToDo: Connect to EPM by restAPI and retrive the info from the EPM Console
function Get-UsersAndGroupsFromPolicy {

    param (
        [PSCustomObject]$policyObjects
    )    

    Write-Host "Search for invalid users\groups" -ForegroundColor DarkGray
    foreach ($platform in $policyObjects.Keys) {
        Write-Host "Processing $platform Policies" -ForegroundColor DarkGray
        foreach ($policyObject in $policyObjects[$platform]) {
            # Check only if the field user is used
            if ($policyObject.Users) {

                # Check if the Connection to EPM Console is valid, in that case use the info from console
                if ($auth) {
                    foreach ($EPMpolicy in $policiesFromEPM.Policies) {
                        if ($EPMpolicy.PolicyName -eq $($policyObject.'Policy name')){
                            $policyDetails = Invoke-RestMethod -Uri "$managerURL/EPM/API/Sets/$setID/Policies/Server/$($EPMpolicy.PolicyId)" -Method 'GET' -Headers $sessionHeader
                            foreach ($account in $policyDetails.Policy.Accounts){
                                if ([string]::IsNullOrEmpty($account.Sid)) {
                                    Write-Host " - $($policyObject.'Policy name'): $($account.DisplayName) SID is null, please review the configuration" -ForegroundColor Red
                                }
                                if ($account.SamName -notmatch ".*\\.*"){
                                    Write-Host " - $($policyObject.'Policy name'): $($account.DisplayName) value is invalid, replace with domain\username form" -ForegroundColor Red
                                }
                            }
                            Start-Sleep -Seconds 10
                        }
                    }
                }
                else {
                    $users = $policyObject.Users -split ','
                    foreach ($user in $users) {
                        # If user definition is not valid trigger the warning
                        if ($user -notmatch ".*\\.*"){
                            Write-Host " - $($policyObject.'Policy name'): $user value is invalid, replace with domain\username form" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }
}

# Search applications with similar properties, under constructions
function Get-SimilarApplications {
    param (
        [PSCustomObject]$applicationsData
    )

    Write-Output "Check for duplicated definitions"

    # Loop through the applications list and search for similar application
    foreach ($application in $applicationsData) {
        Compare-Properties -targetString $application.'File Name' -targetCompare $application.'File Name Compare As' -searchString $application.'File Name' -searchCompare $application.'File Name Compare As'
<#
        # Search for Filename config by RegEx
        if ($application.'File Name Compare As' -eq 'RegExp'){
            
            Write-Output "*** Check for RegEx"
            Write-Output "** Definition Name: $($application.'File Name')"
            Write-Output "** Policy Name: $($application.'Policy name')"

            # Search if there any match with other application name
            foreach ($searchApp in $applicationsData) {
                

                if ($searchApp.'File Name Compare As' -ne 'RegEx'){
                    if ($searchApp.'File Name' -match $application.'File Name') {
                        Write-Output "$($searchApp.'File Name'): found possible match with $($application.'File Name')"
                        Write-Output "Policy Name: $($application.'Policy name')"
                       # Write-Output "File Name: $($application.'File Name')"
                    }
                }
#>
            }

<#
            # Search if there any match with other application name
            foreach ($searchApp in $applicationsData) {
                if ($searchApp.'File Name Compare As' -ne 'RegEx'){
                    if ($searchApp.'File Name' -match $application.'File Name') {
                        Write-Output "$($searchApp.'File Name'): found possible match with $($application.'File Name')"
                        Write-Output "Policy Name: $($application.'Policy name')"
                       # Write-Output "File Name: $($application.'File Name')"
                    }
                }
            }
        }

        # Search for Filename config by Wildcards
        elseif ($application.'File Name Compare As' -eq 'Wildcards' -and !$application.checksum){
            
            Write-Output "*** Check for Wildcards"
            Write-Output "** Definition Name: $($application.'File Name')"
            Write-Output "** Policy Name: $($application.'Policy name')"
            
            # Check if the string is a wildcard compatible
            if ($application.'File Name' -notlike "*[*?]*"){
                Write-Output "$($application.'File Name') -> Not a Wildcard!!"
            }
            else {
                foreach ($searchApp in $applicationsData) {
                    if ($searchApp.'File Name Compare As' -ne 'Wildcards'){
                        if ($searchApp.'File Name' -like $application.'File Name') {
                            Write-Output "$($searchApp.'File Name'): found possible match with $($application.'File Name')"
                            Write-Output "Policy Name: $($application.'Policy name')"
                        }
                    }
                }
            }
        }

        # Search for Filename config by Contains
        elseif ($application.'File Name Compare As' -eq 'Contains') {
            if (!$application.Checksum -or !$application.Publisher) {
                Write-Output "*** Check for Contains"
                Write-Output "** Definition Name: $($application.'File Name')"
                Write-Output "** Policy Name: $($application.'Policy name')"
                $containsSearch = $application.'File Name'
                foreach ($application in $applicationsData) {
                    if ($application.'File Name Compare As' -eq 'Exactly'){
                        if ($application.'File Name' -match ".*$containsSearch.*") {
                            Write-Output "Found possible match"
                            Write-Output "Policy Name: $($application.'Policy name')"
                            Write-Output "File Name: $($application.'File Name')"

                        }
                    }
                }
            }
        }
    }
#>
}

# Used by Get-SimilarApplications function to compare fields - under construction
Function Compare-Properties {
    param (
        [string]$targetString,
        [string]$targetCompare,
        [string]$searchString,
        [string]$searchCompare
    )

   # Write-Host "$($searchString): String to check" -ForegroundColor Blue

    switch ($searchCompare) {
<#        
        'Exactly' {
            if ($targetString -eq $searchString) { 
                Write-Output "$($targetString): found possible match with $searchString"
            }
          }
        'Contains' {  
            if ($targetString -like ".*$searchString.*") {
                Write-Output "$($targetString): found possible match with $searchString"
            }
        }
        'Prefix' {  
            if ($targetString -like ".*$searchString") {
                Write-Output "$($targetString): found possible match with $searchString"
            }
        }
#>
        'RegExp' {  
            #Write-Host "Target string: $($targetString) - Searching match for RegEx" -ForegroundColor Yellow
            $compare = $false
            switch ($targetCompare) {
                'Exactly' {
                    $compare = $true
                    break
                    }
                
                Default {
                    break
                }
            }
            
            if ($compare){
                if ($targetString -match $searchString) {
                    Write-Host "$($targetString): found match with $searchString" -ForegroundColor Green
                }
                else {
                    Write-Host "$($targetString): no match found with $searchString" -ForegroundColor Red
                }
            }
            else {
                Write-Host "$($targetString) - $($targetCompare) not supported with this version, please chek manually" -ForegroundColor Yellow
            }
        }

        'Wildcards' {
          #  Write-Host "Found $($targetString): Check for WildCards" -ForegroundColor Yellow
            $compare = $false
            
            switch ($targetCompare) {
                'Exactly' {
                    $compare = $true
                    break
                }
                
                Default {
                    break
                }
            }

            if ($compare){
                if ($targetString -like $searchString) {
                    Write-Host "$($targetString): found match with $searchString" -ForegroundColor Green
                }
                else {
                    Write-Host "$($targetString): no match found with $searchString" -ForegroundColor Red
                }
            }
            else {
                Write-Host "$($targetString) - $($targetCompare) not supported with this version, please chek manually" -ForegroundColor Yellow
            }
        }
        
        Default {
            #Write-Host "$($searchString) - $($searchCompare) not supported with this version, please chek manually" -ForegroundColor Yellow
            break
        }
    }
}


# Function to search app definition based on checksum
function Get-AppChecksum {
    param (
        [string]$policyName
    )

    # Search from "Application Report" the list of application definitions
    $targetApplications = $applicationsData | Where-Object { $_.'Policy name' -eq $policyName }

    # Loop through applications definitions and search for checksum
    foreach ($application in $targetApplications) {
        if ($application.Checksum) {
            Write-Host "  -------"
            if ($application.'File Name') {
                Write-Host "  + File Name: $($application.'File Name')" -ForegroundColor Yellow
            }
            Write-Host "  + Application Type: $($application.'Application Type')" -ForegroundColor Yellow
            Write-Host "  + Checksum: $($application.Checksum)" -ForegroundColor Yellow
            Write-Host "  -------"
        }
    }
}

# Search in the applications certain capabilities (for example: app based on checksum)
function Get-Applications {

    param (
        [PSCustomObject]$policyObjects
    )    

    foreach ($platform in $policyObjects.Keys) {
        Write-Host "Processing $platform Policies" -ForegroundColor DarkGray
        foreach ($policyObject in $policyObjects[$platform]) {
            Write-Host " - Processing $($policyObject.'Policy name')"
            # List application defintion based on Checksum and return the policy name
            Get-AppChecksum -policyName $policyObject.'Policy name'
            Write-Host "========================"    

        }
        Write-Host "========================"    
    }
}

# Split policies by platfrom Type (Window, Linux and MacOS), return hashtable
# As parameter the policy object imported from CSV "Policies Report"
function Split-PolicyByPlatform {

    param (
        [PSCustomObject]$policyObjects
    )

    $policyWindowsObjects = @()
    $policyLinuxObjects = @()
    $policyMacOSObjects = @()
    $policyDefault = @()

    foreach ($row in $policyObjects) {
        switch -regex ($row.'Policy Type'){
            '.*Windows.*' {
                $policyWindowsObjects +=$row;
                Break
            }
            '.*Linux.*' {
                $policyLinuxObjects +=$row;
                Break
            }
            '.*MacOS.*' {
                $policyMacOSObjects +=$row;
                Break
            }
            Default {
                $policyDefault +=$row;
            }
        }
    }
    
    # Return the split policy objects as a hashtable
    @{
        Windows = $policyWindowsObjects
        Linux = $policyLinuxObjects
        MacOS = $policyMacOSObjects
        Default = $policyDefault
    }
}

# Get the policies summary, the total number of policy for each type
function Get-PolicesSummary {
    param (
        [PSCustomObject]$policyObjects
    )    

    foreach ($platform in $policyObjects.Keys) {
        Write-Output "========================"
        Write-Host "Summary of $platform Policies" -ForegroundColor DarkGray
        if ($platform -eq "Default") {
            Get-DefaultPolicyTypeStatus $policyObjects[$platform]
        }
        else {
            Get-PolicyTypeCounter -policyObjects $policyObjects[$platform]
        }
        Write-Output "========================"
    }


}

# Login to EPM Console only if LoginUserName parameter has been specified in the command line
if ($LoginUserName) {

    # login server, update if using different server
    $loginServer = "eu"

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

    $policiesFromEPM = Invoke-RestMethod -Uri "$managerURL/EPM/API/Sets/$setID/Policies/Server/Search?limit=1000" -Method 'POST' -Headers $sessionHeader
}

$applicationsData = Import-Csv -Path '.\Policy_summary_(Predefined)_`[Giulio`]_Ferrovial(cyberark_16)_Applications_Report_26-Jul-23-10-39-48.csv'
$policiesData = Import-Csv -Path '.\Policy_summary_(Predefined)_`[Giulio`]_Ferrovial(cyberark_16)_Policies_Report_26-Jul-23-10-39-48.csv'

# 
$policiesByPlatform = Split-PolicyByPlatform -policyObjects $policiesData


#Get-PolicesSummary -policyObjects $policiesByPlatform
#Get-PolicyAudit -policyObjects $policiesByPlatform
#Get-Applications -policyObjects $policiesByPlatform 
Get-UsersAndGroupsFromPolicy -policyObjects $policiesByPlatform

# Not working
#Get-SimilarApplications -applicationsData $applicationsData





#####
# Accept parameter for the report. To be complted.

<#
try {
    # Unzip the file to the temporary folder
    Expand-Archive -Path $EPMReportPolicies -DestinationPath $tempFolder -Force

    # Get a list of CSV files in the temporary folder
    $csvFiles = Get-ChildItem -Path $tempFolder -Filter "*.csv" -File

    # Loop through the CSV files and load them based on their names
    foreach ($csvFile in $csvFiles) {
        if ($csvFile.Name -like "*Applications*") {
            Read-ApplicationsCSV -csvFilePath $csvFile.FullName
        } elseif ($csvFile.Name -like "*Policies*") {
            Read-PoliciesCSV -csvFilePath $csvFile.FullName
        } else {
            # Handle other CSV files (if needed)
            Write-Output "Ignoring CSV file: $($csvFile.FullName)"
        }
    }
} catch {
    Write-Error "Error occurred: $_"
} finally {
    # Clean up - remove the temporary folder
    #Remove-Item -Path $tempFolder -Force -Recurse
}
#>
####

