<#
.SYNOPSIS
This script processes the BeyondTrust XML file and generates EPM compatibles files.
1. Cover the Application Groups.

.DESCRIPTION
The script reads an BeyondTrust XML file, processes its contents, and generates JSON files representing EPM application groups.

.PARAMETER BeyondTrustFile
The path to the BeyondTrust XML file to be processed.

.NOTES
    Author: Giulio Compagnone
    Company: CyberArk
    Version: 0.1 - INTERNAL
    Date: 08/2025
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$BeyondTrustFile
)

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

function Get-Path {
    param (
        [string]$inputPath
    )

    $isDirectory = $inputPath.TrimEnd() -match '[\\\/]$'

    if ($isDirectory -eq $false) {
        return @{
            $fileName = Split-Path -Path $inputPath -Leaf
            $path = Split-Path -Path $inputPath -Parent
        }
    } else {
        return @{
            $fileName = ""
            $path = $inputPath
        }
    }
}


function Add-Application {
    <#
    .SYNOPSIS
    Creates an application object based on the xml node.

    .DESCRIPTION
    This function creates an application object based on all paramteres provided the BeyondTrust application node.

    .PARAMETER description
    A description of the application.
    #>

    param (
        [Parameter(Mandatory = $true)]    
        [System.Xml.XmlElement]$AppNode
    )

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
        "isEmpty" = $false
        "content" = ""
        "compareAs" = 2
        "caseSensitive" = $false
    }

    #PUBLISHER
    $publisherPattern =  @{
        "@type" = "Publisher"
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
        "onlyEmptyValue" = $false
        "isEmpty" = $false
        "signatureLevel" = 2
        "separator" = ";"
    }

    $locationPattern = @{
        "@type" = "Location"
        "content" = ""
        "withSubfolders" = $true
        "caseSensitive" = $false
        "isEmpty" = $false
    }
    
    $adminTaskPattern = @{
        "@type" = "WinAdminTask"
        "taskIds" = [System.Collections.ArrayList]@()
        "isEmpty" = $false    
    }

    #ARGUMENTS
    $argumentsPattern = @{
        "@type" = "Text"
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
        "isEmpty" = $false
    }

    #PRODUCT_NAME
    $productNamePattern = @{
        "@type" = "FileInfo"
        "elementName" = "FileVerInfo"
        "attributeInfoName" = "ProductName"
        "isEmpty" = $false
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
    }

    #CLSID
    $CLSIDPattern = @{ 
        "@type" = "Text"
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
        "isEmpty" = $false
    }

    # FILE_VERSION
    $fileVersionPattern = @{
        "@type" = "VersionRange"
        "minVersion" = ""
        "maxVersion" = ""
        "isEmpty" = $false
    }

    # PRODUCT_VERSION
    $productVersionPattern = @{
        "@type" = "VersionRange"
        "minVersion" = ""
        "maxVersion" = ""
        "isEmpty" = $false
    }

    #FILE_DESCRIPTION
    $fileDescriptionPattern = @{ 
        "@type" = "FileInfo"
        "elementName" = "FileVerInfo"
        "attributeInfoName" = "FileDescription"
        "isEmpty" = $false
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
    }

    # ARGUMENTS
    $argumentsPattern = @{
        "@type" = "Text"
        "content" = ""
        "compareAs" = 0
        "caseSensitive" = $false
        "isEmpty" = $false
    }
    
    # Application Group Template
    $appObject = @{
        "id" = "00000000-0000-0000-0000-000000000000"
        "internalId" = 0
        "internalIndex" = 0
        "applicationType" = 3
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
        "restrictOpenSaveFileDialog" = $true
        "securityTokenId" = "00000000-0000-0000-0000-000000000000"
        "protectInstalledFiles" = $false
        "securityLevel" = "LOW"
    }

    function Add-FileName {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )
        
        # Check for the CheckFileName properties to check if the FileName is used
        if ($properties.CheckFileName -eq "true") {
            
            # Split filename and path
            $isDirectory = $properties.FileName -match '[\\\/]$'

            if ($isDirectory -eq $false) {
                $fileName = Split-Path -Path $properties.FileName -Leaf
                $path = Split-Path -Path $properties.FileName -Parent
        
            } else {
                $fileName = ""
                $path = $properties.FileName
            }
        
            # Case 1: Regex
            if ($properties.FileStringMatchType -eq "RegExp"){
                $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()
                $appObject.patterns.FILE_NAME.content = $properties.FileName
                $appObject.patterns.FILE_NAME.compareAs = 4 # Regex
            } else {
                # Case 2: The input is a path with a filename, and the filename may contains a wildcard.
                # This condition also catches the single asterisk case ("*").
                if ($fileName -ne "") {
                    # Create the Filename
                    $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()
                    
                    # Add filename value
                    $appObject.patterns.FILE_NAME.content = $fileName
                    # Check if The filename contains a wildcard
                    if (($fileName) -match ".*\*") {
                        $appObject.patterns.FILE_NAME.compareAs = 3 # Wildcard
                    } elseif ($properties.FileStringMatchType -eq "Contains") {
                        $appObject.patterns.FILE_NAME.compareAs = 2 # Contains
                    } elseif ($properties.FileStringMatchType -eq "Exact") {
                        $appObject.patterns.FILE_NAME.compareAs = 0 # Exact
                    }
                    # Add the Location if the filename include the the path 
                    if ($path -ne "") {
                        $appObject.patterns."LOCATION" = $locationPattern.Clone()
                        $appObject.patterns.LOCATION.content = $path
                    }
                } else {
                    # Case 3: The input is a directory path without a filename
                    $appObject.patterns."LOCATION" = $locationPattern.Clone()
                    $appObject.patterns.LOCATION.content = $properties.FileName
                }
            }

            # Add the checksum if available
            if ($properties.CheckHash -eq "true") {
                # Create the FILENAME object if not present
                if ($null -eq $appObject.patterns.FILE_NAME ) {
                    $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()
                }
                $appObject.patterns.FILE_NAME.hashAlgorithm = "SHA1"
                $appObject.patterns.FILE_NAME.hash = $properties.FileHash
            }
        }
    }

    function Add-FileName-Script {
        param (
            [Parameter(Mandatory = $true)]    
            $properties,

            [Parameter(Mandatory = $true)]    
            $scriptType
        )

        switch ($scriptType) {
            "wsh" {
                $extension = "*.vbs"
                break
            }
            "ps1" {
                $extension = "*.ps1"
                break
            }
            "bat" {
                $extension = "*.bat"
                break
            }
            default: {
                throw "Wrong value. The argument in -scriptType '$scriptType' does not belong to the allowed values: vbs, ps1, or bat."
            }
        }

        if ($properties.CheckFileName -eq "true") {

            # Create filename object
            $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()

            if ($properties.FileName -ne "*") {

                $isDirectory = $properties.FileName.TrimEnd() -match '[\\\/]$'

                if ($isDirectory -eq $false) {
                    $fileName = Split-Path -Path $properties.FileName -Leaf
                    $path = Split-Path -Path $properties.FileName -Parent
                } else {
                    $fileName = ""
                    $path = $properties.FileName
                }

                # Create filename object
                $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()

                if ($fileName -ne "") {
                    $appObject.patterns.FILE_NAME.content = $fileName
                } else {
                    # case full path without a filename
                    $appObject.patterns.FILE_NAME.content = $extension
                    $appObject.patterns.FILE_NAME.compareAs = 3
                }
                    # Location is mandatory in this case as part of the filename                    
                    $appObject.patterns."LOCATION" = $locationPattern.Clone()
                        $appObject.patterns.LOCATION.content = $path
            } else {
                $appObject.patterns.FILE_NAME.content = $extension
                $appObject.patterns.FILE_NAME.compareAs = 3
            }
        }
    }
    function Add-Publisher {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )
        
        # Add Publisher if available
        if ($properties.CheckCertificate -eq "true") {
            $appObject.patterns."PUBLISHER" = $publisherPattern.Clone()
            if ($properties.Certificate -ne "*") {
                $appObject.patterns.PUBLISHER.content = $properties.Certificate
                if ($properties.CertificateStringMatchType -eq "Contains") {
                    $appObject.patterns.PUBLISHER.compareAs = 2 # Contains
                } elseif ($properties.CertificateStringMatchType -eq "Exact") {
                    $appObject.patterns.PUBLISHER.compareAs = 0 # Exactly
                }
            } else {
                # Any Publisher
                $appObject.patterns.PUBLISHER.signatureLevel = 0
            }
        }
    }

    function Add-ProductName {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )

        # Add Product Name if available
        if ($properties.CheckProductName -eq "true") {
            # Add the Pattern
            $appObject.patterns."PRODUCT_NAME" = $productNamePattern.Clone()
            $appObject.patterns.PRODUCT_NAME.content = $properties.ProductName
            
            if ($properties.ProductNameStringMatchType -eq "Contains") {
                $appObject.patterns.PRODUCT_NAME.compareAs = 2 # Contains
            } elseif ($properties.ProductNameStringMatchType -eq "Exact") {
                    $appObject.patterns.PRODUCT_NAME.compareAs = 0 # Exactly
            }          
            # if product name is wildcard, the compareAs must be update according
            if ($properties.ProductName -eq "*") {
                $appObject.patterns.PRODUCT_NAME.compareAs = 3
            }
        }
    }

    function Add-Arguments {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )

        # Add Product Name if available
        if ($properties.CheckCmdLine -eq "true") {
            # Add the Pattern
            $appObject.patterns."ARGUMENTS" = $argumentsPattern.Clone()
            $appObject.patterns.ARGUMENTS.content = $properties.CmdLine
            if ($properties.CmdStringMatchType -eq "Contains") {
                $appObject.patterns.ARGUMENTS.compareAs = 2 # Contains
            } elseif ($properties.CmdStringMatchType -eq "Exact") {
                    $appObject.patterns.ARGUMENTS.compareAs = 0 # Exactly
            } elseif ($properties.CmdStringMatchType -eq "RegExp") {
                    $appObject.patterns.ARGUMENTS.compareAs = 4 # RegEx
            }
        }
    }

    function Add-FileDescription {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )

        # Add Product Name if available
        if ($properties.CheckProductDesc -eq "true") {
            # Add the Pattern
            $appObject.patterns."FILE_DESCRIPTION" = $fileDescriptionPattern.Clone()
            $appObject.patterns.FILE_DESCRIPTION.content = $properties.ProductDesc
            if ($properties.ProductDescStringMatchType -eq "Contains") {
                $appObject.patterns.FILE_DESCRIPTION.compareAs = 2 # Contains
            } elseif ($properties.ProductDescStringMatchType -eq "Exact") {
                    $appObject.patterns.FILE_DESCRIPTION.compareAs = 0 # Exactly
            } 
              
        }
    }

    function Add-CLSID {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )  
        # Check for the CLSID
        if ($properties.CheckCLSID -eq "true") {
            if ($properties.CLSID -ne "*"){
            # CLSID support only Exaclty
                $appObject.patterns."CLSID" = $CLSIDPattern.Clone()
                $appObject.patterns.CLSID.Content = $properties.CLSID
            }
        }
    }

    function Add-FileVersion {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )  
        
        if ($properties.CheckMinFileVersion -eq "true" -or $properties.CheckMaxFileVersion -eq "true") {
            
            $appObject.patterns."FILE_VERSION" = $fileVersionPattern.Clone()
            
            if ($properties.CheckMinFileVersion -eq "true" -and $properties.MinFileVersion -ne "") {
                $appObject.patterns.FILE_VERSION.minVersion = $properties.MinFileVersion
            }
            
            if ($properties.CheckMaxFileVersion -eq "true" -and $properties.MaxFileVersion -ne "") {
                $appObject.patterns.FILE_VERSION.maxVersion = $properties.MaxFileVersion
            }
        }
    }

    function Add-ProductVersion {
        param (
            [Parameter(Mandatory = $true)]    
            $properties
        )  
        
        if ($properties.CheckMinProductVersion -eq "true" -or $properties.CheckMaxProductVersion -eq "true") {
            
            $appObject.patterns."PRODUCT_VERSION" = $productVersionPattern.Clone()
            
            if ($properties.CheckMinProductVersion -eq "true" -and $properties.MinProductVersion -ne "") {
                $appObject.patterns.PRODUCT_VERSION.minVersion = $properties.MinProductVersion
            }
            
            if ($properties.CheckMaxProductVersion -eq "true" -and $properties.MaxProductVersion -ne "") {
                $appObject.patterns.PRODUCT_VERSION.maxVersion = $properties.MaxProductVersion
            }
        }
    }

    function Add-DefaultPatternIfEmpty {
        param(    
            [Parameter(Mandatory = $true)]  
            $appObject
        )  
        
        if ($appObject.patterns.Count -eq 0) {
            $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()
            $appObject.patterns.FILE_NAME.content = "*" 
            $appObject.patterns.FILE_NAME.compareAs = 3
        }
    }

    foreach ($properties in $AppNode) {
        
        $isTypeSuppored = $true

        # Write-Host "Processing $($properties.Description)..."
        
        # Identify the application type
        switch ($properties.type) {
            "exe" {
                $appObject.applicationType = 3
                Add-FileName -properties $properties
                Add-ProductName -properties $properties
                Add-Publisher -properties $properties
                Add-Arguments -properties $properties
                Add-FileVersion -properties $properties
                Add-ProductVersion -properties $properties
                Add-FileDescription -properties $properties
                Add-FileVersion -properties $properties
                break
            }            
            "msc" {
                # Define the executable type
                $appObject.applicationType = 3
                # Define File name mmc.exe
                $appObject.patterns."FILE_NAME" = $fileNamePattern.Clone()
                $appObject.patterns.FILE_NAME.content = "mmc.exe"
                # Define publisher MS Windows
                $appObject.patterns.Add("PUBLISHER", $publisherPattern)
                $appObject.patterns.PUBLISHER.content = "Microsoft Windows"
                # Define the Argument only in case the file name contain the path and msc file
                if ($properties.FileName -ne "*") {
                    $appObject.patterns."ARGUMENTS" = $argumentsPattern.Clone()
                    $appObject.patterns.ARGUMENTS.content = (Split-Path -Path $properties.FileName -Leaf) # Remove the path
                    $appObject.patterns.ARGUMENTS.compareAs = 2 # Contains
                }
                break
            }
            { $_ -in @("wsh", "ps1", "bat") } {
                $appObject.applicationType = 4
                Add-FileName-Script -properties $properties -scriptType $properties.type
                Add-Publisher -properties $properties
                Add-DefaultPatternIfEmpty -appObject $appObject
                break
            }
            "com" {
                $appObject.applicationType = 15

                # Adding supported properties
                Add-FileName -properties $properties
                Add-Publisher -properties $properties
                Add-CLSID -properties $properties
                Add-Arguments -properties $properties
                Add-DefaultPatternIfEmpty -appObject $appObject
                break                
            }
            "msi" {
                # Define as an msi
                $appObject.applicationType = 5

                # Adding supported properties
                Add-FileName -properties $properties
                Add-ProductName -properties $properties
                Add-Publisher -properties $properties
                Add-Arguments -properties $properties
                Add-FileVersion -properties $properties
                Add-ProductVersion -properties $properties
                Add-FileDescription -properties $properties
                Add-FileVersion -properties $properties
                break
            }
            { $_ -in @("reg", "cpl", "appx", "ocx", "svc") } {
                Write-Host "Nothig to do with $($properties.type) type" -ForegroundColor Yellow
                $isTypeSuppored = $false
                break
            } 
            "unex" {
                # Control Panel -> Uninstall
                $appObject.applicationType = 8
                $appObject.patterns."ADMIN_TASK_ID" = $adminTaskPattern.Clone()
                $appObject.patterns.ADMIN_TASK_ID.taskIds.Add(8)
                break
            }
            Default {
                Write-Host "$($properties.type) type not valid" -ForegroundColor Red
                $isTypeSuppored = $false
                break
            }
        }

        if ($isTypeSuppored -eq $true) {
            # Add description if available
            if ($null -ne $properties.Description -and $properties.Description -ne "") {
                $appObject.description = $properties.Description
            }

            #Set Dialot Right
            $appObject.restrictOpenSaveFileDialog = [bool]$properties.OpenDlgDropRights
            
            # Define child process
            $appObject.childProcess = [bool]$properties.ChildrenInheritToken

            return $appObject
        }
    }
}

# Check if the XML file exists
if (-not (Test-Path $BeyondTrustFile -PathType Leaf)) {
    Write-Error "Error: File does not exist - $BeyondTrustFile"
    exit 1
}

# Attempt to load the XML content
try {
    $BeyondTrustXMLContent = [xml](Get-Content $BeyondTrustFile)
}
catch {
    Write-Error "Error loading XML content: $_"
    exit 1
}

Write-Host "--- Processing Configuration Attributes ---" -ForegroundColor Cyan

foreach ($appGroupNode in $BeyondTrustXMLContent.Configuration.ApplicationGroups.ChildNodes) {

    Write-Host "Application Group: $($appGroupNode.Name)" -ForegroundColor Yellow
    
    $applicationArray = @()

    # Access the Application elements within this ApplicationGroup
    foreach ($application in $appGroupNode.Application) {
        
        $applicationArray += Add-Application -AppNode $application
    }

    # Store the Application list in the app group
    $appGroup = @{
        "Applications" = $applicationArray
        "PolicyType" = 14
        "Name" = $($appGroupNode.Name)
        "Description" = $($appGroupNode.Description)
    }
    # Generate a filename based on GroupName and Action
    $outputFileName = Remove-InvalidCharacters ("$($BeyondTrustXMLContent.Configuration.PolicyName)-$($appGroupNode.Name).json")

    # Convert the object to JSON
    $appGroupJson = $appGroup | ConvertTo-Json -Depth 10

    # Save JSON content to a file
    $appGroupJson | Set-Content -Path $outputFileName -Force

#    Write-Host "-------------------------------------------------------------------------------------------------------------------"
    Write-Host "EPM Application Group Saved Successful!" -ForegroundColor Green
    Write-Host "Output File: $($outputFileName)" -ForegroundColor Yellow
#    Write-Host "This file can be used in the body of the 'Create application group' CyberArk EPM REST API." -ForegroundColor White
#    Write-Host "Refer to CyberArk EPM documentation: https://docs.cyberark.com/EPM/latest/en/Content/WebServices/CreateAppGroup.htm" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------------------------------------------------------"
}