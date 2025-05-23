<#
.SYNOPSIS
This script processes an AppLocker XML file and generates JSON files with application group information.

.DESCRIPTION
The script reads an AppLocker XML file, processes its contents, and generates JSON files representing application groups.
Each application group contains information about the applications allowed or blocked based on the XML rules.

.PARAMETER xmlFilePath
The path to the AppLocker XML file to be processed.

#>

# Check if the appLockerXMLFile file path is provided as a command-line parameter
param (
    [Parameter(Mandatory = $true)]
    [string]$appLockerXMLFile
)

# Hashtable to store processed objects
$processedObjects = @{}

# Function to create a new object for Application Groups
function New-ApplicationGroupObject {
    <#
    .SYNOPSIS
    Creates a new object for storing information about application groups.

    .DESCRIPTION
    This function creates a new object with properties for GroupName, Action, and Applications.
    The object is added to the hashtable for further processing.

    .PARAMETER GroupName
    The name of the application group.

    .PARAMETER Action
    The action (Allow/Block) associated with the application group.
    #>
    param (
        [string]$GroupName,
        [string]$Action
    )

    # Create a new App group object with the given GroupName and Action
    $newObject = [PSCustomObject]@{
        GroupName    = $GroupName
        Action       = $Action
        Applications = @()
    }

    # Add the new object to the hashtable
    $key = "$($GroupName)-$($Action)"
    $processedObjects[$key] = $newObject

    return $newObject
}

# Function to create the Application Object
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

# Check if the XML file exists
if (-not (Test-Path $appLockerXMLFile -PathType Leaf)) {
    Write-Error "Error: File does not exist - $appLockerXMLFile"
    exit 1
}

# Attempt to load the XML content
try {
    $appLockerXMLContent = [xml](Get-Content $appLockerXMLFile)
}
catch {
    Write-Error "Error loading XML content: $_"
    exit 1
}

# Extract just the filename
$appLockerXMLFileName = (Get-Item $appLockerXMLFile).BaseName


# Access specific elements in the XML structure
foreach ($ruleCollection in $appLockerXMLContent.AppLockerPolicy.RuleCollection) {
    
    $type = $ruleCollection.Type
    
    Write-Host "Processing $type" -ForegroundColor Yellow
    
    # Check for specific types (EXE, MSI, Script)
    if ($type -eq "Exe" -or $type -eq "Msi" -or $type -eq "Script") {
        
        switch ($type) {
            "Exe" { $appType = 3; Break }
            "Msi" { $appType = 5; Break }
            "Script" { $appType = 4; Break }
        }

        # Iterate through elements
        foreach ($rule in $ruleCollection.ChildNodes) {

            Write-Host "-> Processing $($rule.LocalName) - $($rule.Name) - $($rule.Action)" -ForegroundColor White

            if ($rule.LocalName -eq "FileHashRule") {
                Write-Host "$($rule.LocalName) not supported" -ForegroundColor Red
            }
           
            else {
                # Process the Conditions
                foreach ($condition in $rule.Conditions.ChildNodes) {
                    
                    # Check if the object already exists
                    $key = "$($rule.UserOrGroupSid)-$($rule.Action)"
                    if ($processedObjects.ContainsKey($key)) {
                        $appGroupObject = $processedObjects[$key]
                    } else {
                        # Create a new object if not exists
                        $appGroupObject = New-ApplicationGroupObject -GroupName $rule.UserOrGroupSid -Action $rule.Action
                    }
                    
                    # Check for FilePathCondition
                    if ($condition.LocalName -eq "FilePathCondition") {
                        $appGroupObject.Applications += Set-AppObject -appType $appType -location $condition.Path -description $rule.Id
                    } 
                    
                    elseif ($condition.LocalName -eq "FilePublisherCondition") {
                        $appGroupObject.Applications += Set-AppObject -appType $appType -filename $condition.BinaryName -publisher $condition.PublisherName -product $condition.ProductName -description $rule.Id
                        
                        #foreach ($version in $rule.Exceptions.FilePublisherCondition.ChildNodes) {
                        #    $lowVersion = $version.LowSection
                        #    $highVersion = $version.HighSection
                        #}
                    }
                }

                # Process Exceptions subtree
                foreach ($exception in $rule.Exceptions.ChildNodes) {

                    # $exceptionAction - to be verified 
                    # I suppose that Conditions is configured as main action, could allow or block
                    # in this case the exception is the opposite of Conditions
                    if ($rule.Action -eq "Allow") {
                        $exceptionAction = "Block"
                    }

                    elseif ($rule.Action -eq "Block") {
                        $exceptionAction = "Allow"
                    }

                    # Check if the object already exists
                    $key = "$($rule.UserOrGroupSid)-$exceptionAction"
                    if ($processedObjects.ContainsKey($key)) {
                        $appGroupObject = $processedObjects[$key]
                    } else {
                        # Create a new object if not exists
                        $appGroupObject = New-ApplicationGroupObject -GroupName $rule.UserOrGroupSid -Action $exceptionAction
                    }

                    # Check for FilePathCondition
                    if ($exception.LocalName -eq "FilePathCondition") {
                        $appGroupObject.Applications += Set-AppObject -appType $appType -location $exception.Path -description $rule.Id
                    }

                    elseif ($exception.LocalName -eq "FilePublisherCondition") {
                        $appGroupObject.Applications += Set-AppObject -appType $appType -filename $exception.BinaryName -publisher $exception.PublisherName -product $exception.ProductName -description $rule.Id
                        
                        #foreach ($version in $rule.Exceptions.FilePublisherCondition.ChildNodes) {
                        #    $lowVersion = $version.LowSection
                        #    $highVersion = $version.HighSection
                        #}
                    }
                }
            }
        }
    }
}

# Display the resulting objects
# $processedObjects.Values

# Iterate over processed objects
foreach ($object in $processedObjects.Values) {

    # Decode group or username SID
    switch ($object.GroupName) {
        "S-1-1-0" { 
            $UserOrGroup = "AllUsers";
            Break
        }
        "S-1-5-32-544" {
            $UserOrGroup = "DomainAdmins";
            Break
        }
        default {
            $UserOrGroup = $object.GroupName.split('-')[-1];
            Break
        }
    }

    # Merge the block applications array to the final policy structure
    $appGroup = @{
        "Applications" = $object.Applications
        "PolicyType" = 14
        "Name" = "$($UserOrGroup) - $($object.Action) - Win - $($appLockerXMLFileName)"
        "Description" = "Imported from AppLocker $appLockerXMLFileName - $($UserOrGroup) - $($object.Action)"
    }
    # Generate a filename based on GroupName and Action
    $outputFileName = "$($appLockerXMLFileName)-$($UserOrGroup)-$($object.Action).json"

    # Convert the object to JSON
    $appGroupJson = $appGroup | ConvertTo-Json -Depth 10

    # Save JSON content to a file
    $appGroupJson | Set-Content -Path $outputFileName -Force

    Write-Host "-------------------------------------------------------------------------------------------------------------------"
    Write-Host "EPM Application Group Save Successful!" -ForegroundColor Green
    Write-Host "Output File: $($outputFileName)" -ForegroundColor Yellow
    Write-Host "This file can be used in the body of the 'Create application group' CyberArk EPM REST API." -ForegroundColor White
    Write-Host "Refer to CyberArk EPM documentation: https://docs.cyberark.com/EPM/latest/en/Content/WebServices/CreateAppGroup.htm" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------------------------------------------------------"
}
