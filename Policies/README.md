# 💻 EPM Policies Management Scripts

This directory contains PowerShell scripts dedicated to managing CyberArk Endpoint Privilege Manager (EPM) policies and configurations via the official **Endpoint APIs**.

## ⚠️ Prerequisites

## 📜 Scripts Overview

The following table summarizes the scripts available in this directory and their function:

| Script                              | Description                                                                       | Example                                                                                                                                    |
| ----------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **EPMAddApplication.ps1**           | Adds an application definition to an Application Group.                           | `.\EPMAddApplication.ps1 -username "user@domain" -setName "MySet" -tenant "eu"`                                                            |
| **EPMAddComputertoPolicy.ps1**      | Assigns computers to EPM policies based on a CSV file.                            | `.\EPMAddComputertoPolicy.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -policyFile "C:\temp\policy.csv"`                      |
| **EPMAppGroupUpload.ps1**           | Performs bulk upload of Application Group definitions from a CSV.                 | `.\EPMAppGroupUpload.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -destinationFolder "C:\Output"`                             |
| **EPMApplicationUpdateExample.ps1** | Demo script to mass-update application properties (e.g., enable child processes). | `.\EPMApplicationUpdateExample.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -destinationFolder "C:\Output"`                   |
| **EPMCreateJIT.ps1**                | Creates JIT policies based on manual request events.                              | `.\EPMCreateJIT.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -log`                                                            |
| **EPMCreateJITApp.ps1**             | Creates JIT Application policies by reading EPM events.                           | `.\EPMCreateJITApp.ps1 -username "user@domain" -setName "MySet" -tenant "eu"`                                                              |
| **EPMDeletePolicies.ps1**           | Deletes inactive policies created by JIT automation.                              | `.\EPMDeletePolicies.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -destinationFolder "C:\Output"`                             |
| **EPMDuplicateAgentConf.ps1**       | Duplicates an active agent configuration for a new agent.                         | `.\EPMDuplicateAgentConf.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -agentPolicyName "Ubuntu" -destCompName "Ubuntu2204-1"` |
| **EPMFixComputerPolicy.ps1**        | Fixes or deletes a computer object in a policy.                                   | `.\EPMFixComputerPolicy.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -delete`                                                 |
| **EPMGetPolicyTarget.ps1**          | Retrieves policy targets (users, groups, computers).                              | `.\EPMGetPolicyTarget.ps1 -username "user@domain" -setName "MySet" -tenant "eu" -destinationFolder "C:\Output"`                            |


## 🚀 Usage Example

To run a script, provide any required parameters:

```powershell
# Assuming you are in the root directory:
./ScriptName.ps1 -username "LoginUserUPN" -tenant "tenant"


