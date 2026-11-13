@echo off
setlocal EnableDelayedExpansion

:: ======================================================================
:: 1. Administrative Privileges Check
:: ======================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ======================================================================
    echo [!] ERROR: ADMINISTRATOR PRIVILEGES REQUIRED
    echo ======================================================================
    echo This script must be executed with elevated privileges.
    echo Please right-click this batch file and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: ======================================================================
:: 2. Boot Mode Detection
:: ======================================================================
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" >nul 2>&1
if %errorlevel% equ 0 (
    goto :SAFE_MODE_ROUTINE
)
if defined SAFEBOOT_OPTION (
    goto :SAFE_MODE_ROUTINE
)

goto :NORMAL_MODE_ROUTINE

:: ======================================================================
:: 3. Normal Mode Routine: Configure Safe Mode & Reboot
:: ======================================================================
:NORMAL_MODE_ROUTINE
echo ======================================================================
echo STATUS: NORMAL MODE
echo ======================================================================
echo EPM self-defense drivers are active. 
echo To bypass self-defense, services must be disabled from Safe Mode.
echo.

choice /c YN /m "Do you want to configure Safe Mode and reboot now"
if %errorlevel% equ 2 (
    echo.
    echo [!] Aborted by user. No system changes were made.
    pause
    exit /b 0
)

echo.
echo [*] Configuring BCD to boot into Safe Mode...
bcdedit /set {current} safeboot minimal >nul 2>&1
if %errorlevel% neq 0 (
    bcdedit /set {default} safeboot minimal >nul 2>&1
)

if %errorlevel% neq 0 (
    echo [!] ERROR: Failed to update BCD boot parameters.
    pause
    exit /b 1
)

echo [+] Safe Mode flag successfully configured.
echo [*] System will restart in 5 seconds (Press Ctrl+C to abort)...
shutdown /r /t 5 /c "Rebooting into Safe Mode to disable EPM self-defense"
exit /b 0

:: ======================================================================
:: 4. Safe Mode Routine: Disable Services & Restore Normal Boot
:: ======================================================================
:SAFE_MODE_ROUTINE
echo ======================================================================
echo STATUS: SAFE MODE DETECTED
echo ======================================================================
echo Suppressing EPM kernel drivers and service startups...
echo.

:: Primary Driver & Agent Services
echo [*] Disabling vfdrv (Kernel Driver)...
sc config vfdrv start= disabled >nul 2>&1

echo [*] Disabling vfpd (Minifilter Driver)...
sc config vfpd start= disabled >nul 2>&1

echo [*] Disabling vf_agent (EPM Agent Service)...
sc config vf_agent start= disabled >nul 2>&1

:: Legacy / Auxiliary Services (from older versions, ignored if not found)
sc config vfnet start= disabled >nul 2>&1
sc config pasagent start= disabled >nul 2>&1
sc config paagent start= disabled >nul 2>&1

echo [+] Target driver and agent services set to DISABLED.

echo.
echo [*] Restoring BCD boot configuration to Normal Mode...
bcdedit /deletevalue {current} safeboot >nul 2>&1
bcdedit /deletevalue {default} safeboot >nul 2>&1
echo [+] Safe Mode flag removed from BCD.

echo.
echo ======================================================================
echo NEXT STEPS (Upon reboot to Normal Mode):
echo 1. Self-defense drivers will not load.
echo 2. Run standard uninstall via 'Add or Remove Programs'
echo    OR execute directly:
echo    msiexec /x {PRODUCT-GUID-HERE}
echo ======================================================================
echo.

choice /c YN /m "Do you want to reboot into Normal Mode now"
if %errorlevel% equ 2 (
    echo.
    echo Reboot skipped. Remember to restart manually when ready.
    pause
    exit /b 0
)

echo.
echo [*] Rebooting to Normal Mode in 5 seconds...
shutdown /r /t 5 /c "Rebooting to Normal Mode"
exit /b 0