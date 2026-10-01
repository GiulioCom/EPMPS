# 💻 EPM Endpoint Management Scripts

This directory contains PowerShell scripts dedicated to managing CyberArk Endpoint Privilege Manager (EPM) policies and configurations via the official **Endpoint APIs**.

## 📜 Scripts Overview

The following table summarizes the scripts available in this directory and their function:

|Script|Description|Example|
|-|-|-|
|`EPMGetEndpointDetails.ps1`|Retrieve Endpoints Details|
|`EPMMoveComputer.ps1`| Move Computer between SET (old script, rely on old API)|
|`EPMPKGDownloader.ps1`| Download latest EPM Agent Software Package|
|`Get-EPMEndpoints`|Retrieve Endpoints Data|
|`Remove-DuplicateEndpoints.ps1`|Remove Duplicate Endpoints by reading the EPM Report|
|`Remove-EPMEndpoints.ps1`|Remove Endpoints by reading the EPM Report|
|`Sync-EPMEndpointGroup.ps1`|Sync Endpoint Group group by reading a CSV file.|
