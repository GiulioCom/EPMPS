@echo off
setlocal EnableDelayedExpansion

:: ======================================================================
:: 1. Administrative Privileges Check (Safe-Mode Compatible)
:: ======================================================================
reg query "HKU\S-1-5-19" >nul 2>&1
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
:: 3. Normal Mode Routine: Check Service State & Configure Safe Mode
:: ======================================================================
:NORMAL_MODE_ROUTINE
echo ======================================================================
echo STATUS: NORMAL MODE
echo ======================================================================
echo [*] Checking EPM driver and service states...

set "ACTIVE_FOUND=0"
for %%S in (vfdrv vfpd vf_agent vfnet pasagent paagent) do (
    sc query "%%S" 2>nul | find "RUNNING" >nul
    if !errorlevel! equ 0 (
        echo [!] Active component detected: %%S
        set "ACTIVE_FOUND=1"
    )
)

echo.
if "%ACTIVE_FOUND%"=="0" (
    call :FIND_EPM_GUID
    echo [+] All EPM self-defense drivers and agent services are STOPPED.
    echo.
    echo Safe Mode is not required. You can proceed directly with uninstallation:
    echo   1. Open 'Add or Remove Programs' / 'Installed apps'
    echo   2. OR run the detected uninstall command:
    echo      msiexec /x !EPM_GUID!
    echo.

    if /i not "!EPM_GUID!"=="{PRODUCT-GUID-NOT-FOUND}" (
        choice /c YN /m "Do you want to launch the EPM uninstaller now"
        if !errorlevel! equ 1 (
            echo [*] Launching msiexec /x !EPM_GUID! ...
            start "" msiexec.exe /x !EPM_GUID!
            exit /b 0
        )
    ) else (
        pause
    )
    exit /b 0
)

echo EPM self-defense drivers/services are currently active.
echo To bypass self-defense, they must be disabled from Safe Mode.
echo.

choice /c YN /m "Do you want to configure Safe Mode and reboot now"
if %errorlevel% equ 2 (
    echo.
    echo [!] Aborted by user. No system changes were made.
    echo To manually configure Safe Mode later, run:
    echo   bcdedit /set {current} safeboot minimal
    echo.
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
    echo     Check BitLocker or third-party boot protection policies.
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

call :FIND_EPM_GUID

echo.
echo ======================================================================
echo NEXT STEPS (Upon reboot to Normal Mode):
echo 1. Self-defense drivers will not load.
echo 2. Run standard uninstall via 'Add or Remove Programs'
echo    OR execute the detected uninstall command:
echo    msiexec /x !EPM_GUID!
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


:: ======================================================================
:: 5. Subroutine: Dynamically Locate EPM Product GUID from Registry
:: ======================================================================
:FIND_EPM_GUID
set "EPM_KEY="
set "EPM_GUID="
set "UNINST_STR="

for %%R in (
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
) do (
    for /f "tokens=*" %%K in ('reg query %%R /s /f "CyberArk Endpoint Privilege Manager Agent" /d /e 2^>nul ^| findstr /i "^HKEY_"') do (
        set "EPM_KEY=%%K"
    )
)

if defined EPM_KEY (
    for /f "tokens=2*" %%A in ('reg query "!EPM_KEY!" /v UninstallString 2^>nul ^| findstr /i "UninstallString"') do (
        set "UNINST_STR=%%B"
    )
    if defined UNINST_STR (
        for /f "tokens=2 delims={}" %%G in ("!UNINST_STR!") do (
            set "EPM_GUID={%%G}"
        )
    )
)

if not defined EPM_GUID (
    set "EPM_GUID={PRODUCT-GUID-NOT-FOUND}"
)
exit /b 0