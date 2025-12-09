# 💻 EPM Policies Management Scripts

This directory contains PowerShell scripts dedicated to managing CyberArk Endpoint Privilege Manager (EPM) policies and configurations via the official **Endpoint APIs**.

## ⚠️ Prerequisites

## 📜 Scripts Overview

The following table summarizes the scripts available in this directory and their function:

| Script Name                               | Description                                                                    | 
| `EPMAddApplication.ps1`                   | Add Application in policy
| `EPMAddComputerToPolicy.ps1`              | 
| `EPMAppGroupUpload.ps1`                   |
| `EPMApplicationUpdateExample.ps1`         |
| `EPMCreateJIT.ps1`                        |
| `EPMCreateJITApp.ps1`                     |   
| `EPMDeletePolicies.ps1`                   |
| `EPMDuplicateAgentConf.ps1`               |
| `EPMFixComputerPolicies.ps1`              |
| `EPMGetPoliciesTarget.ps1`                |
| `EPMPoliciesBackup.ps1`                   |
| `EPMPoliciesImport.ps1`                   |
| `EPMPoliciesRestore.ps1`                  |
| `EPMPoliciesSync.ps1`                     |
| `EPMPolicyUpdate.ps1`                     |
| `EPMPolicyValidator.ps1`                  |

## 🚀 Usage Example

To run a script, provide any required parameters:

```powershell
# Assuming you are in the root directory:
./ScriptName.ps1 -username "LoginUserUPN" -tenant "tenant"


