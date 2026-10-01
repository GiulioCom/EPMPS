# Allowed MSI success exit codes (0 = Success, 3010 = Reboot required)
$successCodes = @(0, 3010)
$proceedWithInstall = $true

# --- 1. UNINSTALL EXISTING VERSION ---
$appName = "*CyberArk Endpoint Privilege Manager*"
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$app = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -like $appName -and $_.PSChildName -match '^\{[A-F0-9-]{36}\}$' } | 
    Select-Object -First 1

if ($app) {
    $guid = $app.PSChildName
    Write-Host "Uninstalling existing version ($guid)..." -ForegroundColor Yellow

    $token = "***********************"   # Add the secure Token here
    $uninstallArgs = "/X $guid FULL_UNINSTALL=`"YES`" SECURE_TOKEN=`"$token`" /qn /l*V `"C:\EPM_uninstall.log`""
    
    try {
        $unproc = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -PassThru
        
        # Check if exit code indicates success
        if ($successCodes -contains $unproc.ExitCode) {
            Write-Host "Uninstall successful (Exit Code: $($unproc.ExitCode))." -ForegroundColor Green
        } else {
            Write-Error "Uninstall failed with Exit Code: $($unproc.ExitCode). Aborting installation."
            $proceedWithInstall = $false
        }
    } catch {
        Write-Error "Failed to execute uninstall process: $_"
        $proceedWithInstall = $false
    }
} else {
    Write-Host "No existing installation found. Proceeding with fresh install..." -ForegroundColor Yellow
}

# --- 2. INSTALL NEW VERSION ---
if ($proceedWithInstall) {
    $msiPath = "<path_to_msi>\VFAgentSetupX64.msi"
    $installKey = "***********************"  # Add the secure Installation Key here
    $configFile = "<path_to_config>\CyberArkEPMAgentSetupWindows.config"

    if (Test-Path $msiPath) {
        Write-Host "Starting new installation..." -ForegroundColor Green
        
        $installArgs = "/i `"$msiPath`" INSTALLATIONKEY=`"$installKey`" CONFIGURATION=`"$configFile`" /qn /l*V `"C:\EPM_install.log`""
        $inproc = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
        
        if ($successCodes -contains $inproc.ExitCode) {
            Write-Host "Installation completed successfully (Exit Code: $($inproc.ExitCode))." -ForegroundColor Green
        } else {
            Write-Error "Installation failed with Exit Code: $($inproc.ExitCode)."
        }
    } else {
        Write-Error "Installer file not found at $msiPath"
    }
} else {
    Write-Warning "Installation skipped because the uninstall phase reported errors."
}