# 💻 EPM Endpoint Management Scripts

This directory contains PowerShell scripts dedicated to managing CyberArk Endpoint Privilege Manager (EPM) policies and configurations via the official **Endpoint APIs**.

## ⚠️ Prerequisites

## 📜 Scripts Overview

The following table summarizes the scripts available in this directory and their function:

| Script Name | Description | 
| :--- | :--- | :--- |
| `EPMDeleteDuplicateComputer` | Remove Duplicate Computer (MyComputer) or Endpoints (Endpoints) in EPM Console |
| `EPMDeleteDuplicateEndpointsFromFile.ps1` | Remove Duplicate Endpoints (Endpoints) reading from the report. |
| `EPMGetEndpointDetails.ps1` | Retrieve Endpoints Details |
| `EPMPKGDownloader.ps1` | Download latest EPM Agent Software Package |
| `EPMSyncComputerGroup.ps1` | Sync computer group by reading a CSV file. |


## 🚀 Usage Example

To run a script, provide any required parameters:

```powershell
# Assuming you are in the root directory:
./ScriptName.ps1 -username "LoginUserUPN" -tenant "tenant"