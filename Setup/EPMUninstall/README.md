# Idira EPM Agent Emergency Cleanup

This repository contains the modernized batch script (`EPMUninstallCleanup.bat`) designed to safely remove the CyberArk Endpoint Privilege Manager (EPM) agent in emergency scenarios where standard uninstallation methods (via the GUI or Secure Token) fail or become unresponsive.

## ⚖️ Legal & Personal Disclaimer

**This repository and its contents are strictly a personal project.** This script is not supported by Palo Alto Networks or CyberArk. 

The scripts and information provided here are offered "as-is" without warranty of any kind. By using this script, you assume all responsibility and risk. Neither the author nor Palo Alto Networks can be held liable for any damages, system instability, or data loss resulting from the use of these materials.

## ⚠️ Important Usage Disclaimer

**This procedure should only be used as a last resort.** The standard, supported method to uninstall the EPM Agent is through the EPM Console or locally using a Secure Token (`msiexec /x {ProductCode} SECURE_TOKEN=generated_token /qn`). Use this script only if those methods fail.

## Why This Script is Necessary

Legacy cleanup documentation often instructed users to boot into Safe Mode and manually delete `C:\Windows\System32\drivers\vfpd.sys`.

In modern Windows architectures, EPM kernel drivers are staged dynamically inside the protected Windows Driver Store (`FileRepository`). Manually deleting files breaks package integrity and causes Registry orphan states. This script modernizes the emergency cleanup by leaving the files intact and instead **disabling the EPM services and kernel drivers directly** via the Service Control Manager, effectively neutralizing the agent's self-defense mechanisms.

## Prerequisites

* **Administrator Privileges:** The script must be run from an elevated Command Prompt.
* **Local Access:** You will need local console access to the machine (or a hypervisor console) to log in while the machine is in Safe Mode.

## Execution Sequence

To successfully remove the agent, the script must be executed in a specific sequence across three distinct phases.

### Phase 1: Normal Mode (Preparation)

1. Boot normally and open **Command Prompt as Administrator**.
2. Execute `EPMUninstallCleanup.bat`.
3. The script will detect it is in Normal Mode and verify that the EPM self-defense drivers are actively running.
4. Press **Y** when prompted. The script will automatically configure the Windows Boot Configuration Data (BCD) to boot into Safe Mode (Minimal) and restart the machine.

### Phase 2: Safe Mode (Suppress Self-Defense)

1. Log into Windows in **Safe Mode**.
2. Execute `EPMUninstallCleanup.bat` again.
3. The script will detect the Safe Mode environment. It will disable the core EPM services (`vfdrv`, `vfpd`, `vf_agent`, etc.) so they do not load on the next boot.
4. The script will automatically remove the Safe Mode boot flag and prompt for a reboot. Press **Y** to restart the machine back into Normal Mode.

### Phase 3: Normal Mode (Uninstallation)

1. Log into Windows in **Normal Mode**. (The agent's self-defense is now deactivated).
2. Open **Command Prompt as Administrator** and execute `EPMUninstallCleanup.bat` one final time.
3. The script will verify that all EPM components are `STOPPED`.
4. It will dynamically scan the Registry to locate your specific EPM Agent `ProductCode` (GUID).
5. Press **Y** when prompted to launch the uninstaller (`msiexec /x {GUID}`). The uninstall will now complete successfully without prompting for a Secure Token.

## Script Details

The script performs the following core actions in Safe Mode:

* Disables the Kernel Driver: `sc config vfdrv start= disabled`
* Disables the Minifilter Driver: `sc config vfpd start= disabled`
* Disables the User-mode Service: `sc config vf_agent start= disabled`