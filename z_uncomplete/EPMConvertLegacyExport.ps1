function Set-AppObject {
    <#
    .SYNOPSIS
    Creates an application object based on provided parameters.

    .DESCRIPTION
    This function creates an application object based on parameters such as appType, filename, location, publisher, product, and description.

    .PARAMETER appType
    The type of the application.

    .PARAMETER filename
    The filename associated with the application.

    .PARAMETER location
    The location or path associated with the application.

    .PARAMETER publisher
    The publisher of the application.

    .PARAMETER product
    The product name associated with the application.

    .PARAMETER description
    A description of the application.
    #>
    param (
        [string]$appType,
        [string]$filename,
        [string]$location,
        [string]$publisher,
        [string]$product,
        [string]$description
    )

    #Write-Host "appType is: $($appType)"
    #Write-Host "location is: $($location)"

    $productNamePattern = @{
        "@type" = "FileInfo"
        "elementName" = "FileVerInfo"
        "attributeInfoName" = "ProductName"
        "isEmpty" = $true
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
    }
    
    $fileNamePattern = @{
        "@type" = "FileName"
        "hashAlgorithm" = ""
        "hash" = ""
        "hashSHA256" = ""
        "fileSize" = 0
        "isEmpty" = $true
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
    }

    $publisherPattern =  @{
        "@type" = "Publisher"
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $true
        "onlyEmptyValue" = $false
        "isEmpty" = $true
        "signatureLevel" = 2
        "separator" = ";"
    }

    $locationPattern = @{
        "@type" = "Location"
        "content" = ""
        "withSubfolders" = $true
        "caseSensitive" = $true
        "isEmpty" = $false
    }   
    
    # Application Group Template
    $templateAppObject = @{
        "id" = "00000000-0000-0000-0000-000000000000"
        "internalId" = 0
        "internalIndex" = 0
        "applicationType" = 24
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
    
    if ($filename -ne "" -and $filename -ne "*") {
        $templateAppObject.patterns.Add("FILE_NAME", $fileNamePattern)
        $templateAppObject.patterns.FILE_NAME.content = $filename
        # Update compareAs in case filename contain a wildcard
        if ($filename -match ".*\*.*") {
            $templateAppObject.patterns.FILE_NAME.compareAs = 3
        }
    }
    
    if ($product -ne "" -and $product -ne "*") {
        # Script (apptype 4) doesn't support product name
        if ($appType -ne 4) {
            $templateAppObject.patterns.Add("PRODUCT_NAME", $productNamePattern)
            $templateAppObject.patterns.PRODUCT_NAME.content = $product
        }
    }

    if ($location -ne "" -and $location -ne "*") {
        # Use case: location is a folder, applocker string is: c:\folder\*, cleanup is needed
        if ($location.EndsWith('\*')) {
            $templateAppObject.patterns.Add("LOCATION", $locationPattern)
            $templateAppObject.patterns.LOCATION.content = $location.TrimEnd('\*')
        }
        # Use case: location is *.*
        elseif ($location -eq "*.*"){
            $templateAppObject.patterns.Add("FILE_NAME", $fileNamePattern)
            $templateAppObject.patterns.FILE_NAME.content = $location
            $templateAppObject.patterns.FILE_NAME.compareAs = 3
        }
        # Other use case, split the folder name and the filename
        else {
            $templateAppObject.patterns.Add("LOCATION", $locationPattern)
            $templateAppObject.patterns.LOCATION.content = Split-Path $location
            $templateAppObject.patterns.Add("FILE_NAME", $fileNamePattern)
            $templateAppObject.patterns.FILE_NAME.content = Split-Path $location -Leaf
            # Update compareAs in case filename contain a wildcard
            if ($filename -match ".*\*.*") {
                $templateAppObject.patterns.FILE_NAME.compareAs = 3
            }
        }
    }

    if ($publisher -ne "" -and $publisher -ne "*") {
        $templateAppObject.patterns.Add("PUBLISHER", $publisherPattern)
        
        $publisherNameArray = [regex]::Match($publisher, 'O=([^,]+)')
        $publisherName = $publisherNameArray.Groups[1].Value
        
        $templateAppObject.patterns.PUBLISHER.content = $publisherName
    }

    $templateAppObject.description = $description
    $templateAppObject.applicationType = $appType
    
    return $templateAppObject
}


$PolicyActionsHashTable = @{
    "1" = "Normal Run"
    "2" = "Block"
    "3" = "Elevate"
    "4" = "Elevate On Demand"
    "5" = "Collect UAC usage"
    "6" = "Collect Policy Automation"
    "7" = "Log Off"
    "8" = "Computer Action"
    "9" = "Run Script"
    "10" = "Configuration"
    "11" = "Set Security"
    "12" = "Exclude"
    "13" = "Software Distributors"
    "14" = "Restricted Run"
    "15" = "Eagles Policy"
    "16" = "Eagles Policy Global"
    "17" = "LCD"
    "18" = "Multifile Creator"
    "19" = "Exclude for MacOS"
    "20" = "AddToLocalGroup"
}

$PolicyInternalTypeHashTable = @{
    "101" = "DEFAULT_GREY_APPS_ON_ENDUSER_COMPS"
    "103" = "DEFAULT_REMOVABLE_STORAGES"
    "104" = "DEFAULT_DOWNLOADED_FROM_INET"
    "105" = "DEFAULT_REMOVABLE_MONITOR"
    "200" = "DEFAULT_WINDOWS_SYSTEM"
    "201" = "DEFAULT_OLD_APPLICATIONS"
    "202" = "DEFAULT_TEMP_FILES"
    "203" = "DEFAULT_WINDOWS_MONITOR"
    "210" = "TRUSTED_SAMPLE_COMPUTER"
    "220" = "TRUSTED_NETWORK_LOCATION_MAIN"
    "221" = "TRUSTED_NETWORK_LOCATION_INSTALLED"
    "230" = "TRUSTED_PACKAGE_MAIN"
    "231" = "TRUSTED_PACKAGE_INSTALLED"
    "242" = "TRUSTED_DISTRIBUTOR_PREDEFINED"
    "243" = "TRUSTED_DISTRIBUTOR_CUSTOM"
    "244" = "TRUSTED_DISTRIBUTOR_INSTALLED"
    "263" = "TRUSTED_UPDATER_PREDEFINED"
    "264" = "TRUSTED_UPDATER_CUSTOM"
    "265" = "TRUSTED_UPDATER_INSTALLED"
    "280" = "TRUSTED_VENDOR_MAIN"
    "281" = "TRUSTED_VENDOR_INSTALLED"
    "285" = "TRUSTED_PRODUCT"
    "290" = "TRUSTED_USER_OR_GROUP_MAIN"
    "291" = "TRUSTED_USER_OR_GROUP_INSTALLED"
    "300" = "PREDEFINED_APP_GROUP"
    "400" = "CUSTOM_APP_GROUP"
    "500" = "EXPER;Advanced Polic"
    "600" = "CONFIGURATION"
    "700" = "EXCLUDE"
    "800" = "TRUSTED_DISTRIBUTOR_PREDEFINED_DEFINITION"
    "810" = "TRUSTED_DISTRIBUTOR_CUSTOM_DEFINITION"
    "820" = "TRUSTED_UPDATER_PREDEFINED_DEFINITION"
    "830" = "TRUSTED_UPDATER_CUSTOM_DEFINITION"
}


# --- Function to Get Policy Description Details ---
function Get-PolicyDescriptionDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Xml.XmlDocument]$PolicyDescriptionsSection,

        [Parameter(Mandatory=$true)]
        [string]$PolicyIdToSearch
    )

    # Access the PolicyDescriptions section
    #$policyDescriptionsNode = $XmlContent.VfGpoExchange.PolicyDescriptions
    $foundPolicyDescription = $null

    if ($policyDescriptionsNode) {
        # Iterate through each Policy in PolicyDescriptions
        foreach ($descPolicy in $PolicyDescriptionsSection.Policy) {
            # Check if the gpid matches
            if ($descPolicy.gpid -eq $PolicyIdToSearch) {
                $foundPolicyDescription = $descPolicy
                break # Found it, exit loop
            }
        }
    }

    # Create a custom object to return all extracted values
    if ($foundPolicyDescription) {
        [PSCustomObject]@{
            Description             = $foundPolicyDescription.Description
            DefaultApplicationGroup = $foundPolicyDescription.DefaultApplicationGroup
            AllComputers            = [boolean]$foundPolicyDescription.AllComputers
            # Add any other properties you might want to extract from here
        }
    }
    else {
        Write-Warning "No Policy Description found for GPID '$PolicyIdToSearch'."
        return $null # Return null if no matching description is found
    }
}


# Define the path to your XML file.
$xmlFilePath = "c:\Users\giulioc\OneDrive - CyberArk Ltd\Documents\CyberArk Customers\Leonardo\EPM Migration\Policies-29-May-25_08-34-12(Set ELI).xml"

# Check if the file exists before attempting to open it.
if (Test-Path $xmlFilePath) {
    # Load the XML content from the file into an XML object.
    try {
        [xml]$xmlContent = Get-Content $xmlFilePath -Raw

        Write-Host "Successfully loaded XML content from file: $xmlFilePath"
        Write-Host "--------------------------------------------------------"
        Write-Host "--- Processing Policies ---"

        # Access the Policies element
        $policiesNode = $xmlContent.VfGpoExchange.GpoPolicies

        if ($policiesNode) {
            # Iterate through each Policies subchild
            foreach ($policy in $policiesNode.Policy) {
                Write-Host "Policy Name: $($policy.name) - Policy Order: $($policy.order)"
                if ($policy.action) {
                    Write-Host "Policy Action: $($PolicyActionsHashTable[$policy.action])"
                }
                if ($policy.InternalType) {
                    Write-Host "Policy Type: $($PolicyInternalTypeHashTable[$policy.InternalType])"
                } else {
                    Write-Host "Policy Type: Advanced"

                    $policyName = $policy.name
                    
                    # Priority
                    $policyOrder = [int]"$($policy.order[0])0"

                    # Policy Audit
                    if ($policy.reportUsage -and $policy.reportUsage -eq "2") {
                        $policyAudit = $true
                    } else {
                        $policyAudit = $false
                    }

                    # Active
                    $isActive = $true

                    # Policy Type, Windows advanced policy
                    $policyType = 11

                    # Policy Action
                    $policyAction = [int]$policy.action


                    # Get the policy description details
                    $policyDetails = Get-PolicyDescriptionDetails -PolicyDescriptionsSection $xmlContent $xmlContent.VfGpoExchange.PolicyDescriptions $policyIdToSearch
                    $policyNameDescription = $policyDetails.Description
                    #$defaultApplicationGroupVariable = $policyDetails.DefaultApplicationGroup
                    $isAppliedtoAll = $policyDetails.AllComputers

                    # Activation
                    if ($policy.startTime -or $policy.endTime) {
                        if ($policy.startTime) {
                            $policyStartTime = $policy.startTime
                        } else {
                            $policyStartTime = $null
                        }

                        if ($policy.endTime) {
                            $policyEndTime = $policy.endTime
                        } else {
                            $policyEndTime = $null
                        }

                        # Define activation object
                        $activation = @{
                            "ActivateDate" = $policyStartTime
                            "DeactivateDate" = $policyEndTime
                            "Scheduler" = $null
                        }
                    
                    } else {
                        $activation = $null
                    }


                    $ApplicationPolicyTemplate = @{
                        "Audit" = $policyAudit # 
                        "Applications" = $object.Applications
                        "Activation" = $activation #
                        "Priority" = $policyOrder #
                        "Name" = $policyName #
                        "Description" = $policyNameDescription #
                        "PolicyType" = $policyType #
                        "IsActive" = $isActive #
                        "Action" = $policyAction #
                        "Executors" = $object.Executors
                        "IsAppliedToAllComputers" = $isAppliedtoAll #
                        "Accounts" = $object.Accounts
                        "IncludeADComputerGroups" = $IncludeADComputerGroups
                        "ExcludeADComputerGroups" = $ExcludeADComputerGroups
                    }
                }

                Write-Host "---" # Separator for readability


            <#
                # Process Trusted Source
                if ($policy.order -lt 3000) {
                    Write-Host "Policy Name: $($policy.name)"
                    Write-Host "ApplicationGroup Name: $($appGroup.name)"
                    Write-Host "---" # Separator for readability
                }
            #>
            }
        } else {
            Write-Warning "The <ApplicationGroups> section was not found in the XML file."
        }


<#
        # Access the ApplicationGroups element
        $applicationGroupsNode = $xmlContent.VfGpoExchange.ApplicationGroups

        if ($applicationGroupsNode) {
            # Iterate through each ApplicationGroup subchild
            foreach ($appGroup in $applicationGroupsNode.ApplicationGroup) {
                if ($appGroup) {
                    Write-Host "ApplicationGroup ID: $($appGroup.id)"
                    Write-Host "ApplicationGroup Name: $($appGroup.name)"
                    Write-Host "---" # Separator for readability
                }
            }
        } else {
            Write-Warning "The <ApplicationGroups> section was not found in the XML file."
        }
#>
    } catch {
        Write-Error "An error occurred while loading the XML file: $($_.Exception.Message)"
    }
}