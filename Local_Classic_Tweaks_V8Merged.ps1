param(
    [ValidateSet("Minimal", "Full")]
    [string]$Mode
)
# --- Safety Checks ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run from an elevated (Administrator) PowerShell prompt."
    exit 1
}
$ErrorActionPreference = "Stop"
# Prompt if not specified
if (-not $Mode) {
    $Mode = Read-Host "Select tweak mode (Minimal/Full)"
}
# --- Set Time Zone to Central Standard Time ---
try {
    Set-TimeZone -Id "Central Standard Time"
    Write-Host "Time zone set to Central Standard Time (CST/CDT)." -ForegroundColor Cyan
}
catch {
    Write-Warning "Failed to set time zone: $($_.Exception.Message)"
}
# --- Backup Registry Safely ---
function Backup-Registry {
    param (
        [string]$KeyPath,
        [string]$BackupFolder
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeKey = ($KeyPath -replace "[:\\]", "_")
    $backupFile = "$BackupFolder\$safeKey-$timestamp.reg"

    $nativeKeyPath = $KeyPath -replace "^HKCU:", "HKCU" -replace "^HKLM:", "HKLM"
    try {
        reg.exe export "$nativeKeyPath" "$backupFile" /y | Out-Null
        Write-Host "Backup created: $KeyPath => $backupFile" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to backup ${KeyPath}: $($_.Exception.Message)"
    }
}
$backupFolder = "C:\Backup"
if (!(Test-Path $backupFolder)) {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
}
Backup-Registry -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -BackupFolder $backupFolder
Backup-Registry -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -BackupFolder $backupFolder
# --- Apply Registry Tweaks ---
function Apply-RegistryTweaks {
    param ([array]$Tweaks)
    foreach ($tweak in $Tweaks) {
        try {
            if (-not (Test-Path $tweak.Path)) {
                New-Item -Path $tweak.Path -Force | Out-Null
                Write-Host "Created key: $($tweak.Path)" -ForegroundColor Yellow
            }
            Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Type $($tweak.Type)
            Write-Host "Set $($tweak.Path)\$($tweak.Name) to $($tweak.Value)" -ForegroundColor Cyan
        } catch {
            Write-Warning "Failed: $($tweak.Path)\$($tweak.Name): $($_.Exception.Message)"
        }
    }
}
# --- User Tweaks (HKCU) ---
$commonHkcuTweaks = @(
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAl"; Value = 0; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name = "SearchboxTaskbarMode"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"; Name = "EnthusiastMode"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowTaskViewButton"; Value = 0; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"; Name = "PeopleBand"; Value = 0; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "LaunchTo"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Control Panel\Desktop"; Name = "AutoEndTasks"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseHoverTime"; Value = 400; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_Recommendations"; Value = 0; Type = "DWord" },
	@{ Path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"; Name = "HideRecommendedSection"; Value = 1; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"; Name = "ShellFeedsTaskbarViewMode"; Value = 2; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowRecentlyAddedApps"; Value = 0; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowMostUsedApps"; Value = 0; Type = "DWord" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowRecentlyOpenedItems"; Value = 0; Type = "DWord" },
	@{ Path = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"; Name = "(Default)"; Value = ""; Type = "String" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"; Name = "EnthusiastMode"; Value = 1; Type = "DWord" }
)
Apply-RegistryTweaks -Tweaks $commonHkcuTweaks
# --- System Tweaks (HKLM) ---
$commonHklmTweaks = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "LongPathsEnabled"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"; Name = "SearchOrderConfig"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "SystemResponsiveness"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "NetworkThrottlingIndex"; Value = 4294967295; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "IRPStackSize"; Value = 30; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableRecommendations"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "HideRecommendedSection"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightFeatures"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableSoftLanding"; Value = 1; Type = "DWord" }
)
Apply-RegistryTweaks -Tweaks $commonHklmTweaks

# --- Default User Hive Tweaks ---
$defaultHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$defaultHiveKey = "HKEY_USERS\DefaultProfile"
try {
    reg.exe load $defaultHiveKey $defaultHivePath | Out-Null
    Write-Host "Default user hive loaded." -ForegroundColor Green
    $requiredKeys = @(
        "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Search",
        "Registry::$defaultHiveKey\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
        "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $requiredKeys) {
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
            Write-Host "Created missing key: $key" -ForegroundColor Yellow
        }
    }
    Apply-RegistryTweaks @(
        @{ Path = "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAl"; Value = 0; Type = "DWord" },
        @{ Path = "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Search"; Name = "SearchboxTaskbarMode"; Value = 1; Type = "DWord" },
        @{ Path = "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_Recommendations"; Value = 0; Type = "DWord" },
        @{ Path = "Registry::$defaultHiveKey\Software\Policies\Microsoft\Windows\Explorer"; Name = "HideRecommendedSection"; Value = 1; Type = "DWord" },
        @{ Path = "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowTaskViewButton"; Value = 0; Type = "DWord" },
        @{ Path = "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\Education"; Name = "IsEducationEnvironment"; Value = 1; Type = "DWord" }
    )
	# --- Set RunOnce entry INSIDE Default Hive to ensure tweaks for new users ---
    $runOnceCmd = 'powershell -ExecutionPolicy Bypass -Command "'
    foreach ($tweak in $commonHkcuTweaks) {
        $escapedPath = $tweak.Path.Replace('HKCU:\', 'HKCU:\')
        $runOnceCmd += "New-ItemProperty -Path '$escapedPath' -Name '$($tweak.Name)' -Value '$($tweak.Value)' -PropertyType '$($tweak.Type)' -Force; "
    }
    $runOnceCmd += '"'
    Set-ItemProperty -Path "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ApplyUserTweaks" -Value $runOnceCmd -Type String
    Write-Host "Scheduled Default Hive RunOnce for HKCU tweaks." -ForegroundColor Magenta
    # Context menu tweak RunOnce (Classic menu)
    Set-ItemProperty -Path "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "FullContext" -Value 'C:\Windows\System32\cmd.exe /c reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f' -Type String
    # Restart Explorer RunOnce
    Set-ItemProperty -Path "Registry::$defaultHiveKey\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RestartExplorer" -Value 'powershell -Command "Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue"' -Type String
} catch {
    Write-Warning "Failed to load default hive: $($_.Exception.Message)"
} finally {
    $maxRetries = 5
    $unloaded = $false
    for ($i = 1; $i -le $maxRetries; $i++) {
        Stop-Process -Name explorer -Force
        Start-Sleep -Seconds 2  # Add delay after hive edits and before unloading
        $result = reg.exe unload $defaultHiveKey 2>&1
        if ($result -match "successfully") {
            Write-Host "Default user hive unloaded." -ForegroundColor Yellow
            $unloaded = $true
            break
        } else {
            Write-Warning "Attempt ${i}: $result"
            Start-Sleep -Seconds 2
        }
    }
    if (-not $unloaded) {
        Write-Warning "Default hive could not be unloaded after multiple attempts."
    }
}
Start-Process explorer
# --- Disable Scheduled Tasks ---
$scheduledTasks = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
)
#foreach ($task in $scheduledTasks) {
#    $taskExists = (schtasks.exe /Query /TN "$task" 2>&1) -notmatch 'ERROR: The system cannot find the file specified'
#    if ($taskExists) {
#        schtasks.exe /Change /TN "$task" /Disable | Out-Null
#        Write-Host "Disabled task: $task" -ForegroundColor Cyan
#    } else {
#        Write-Warning "Task does not exist: $task"
#    }
#}
foreach ($task in $scheduledTasks) {
    try {
        schtasks.exe /Change /TN "$task" /Disable | Out-Null
        Write-Host "Disabled task: $task" -ForegroundColor Cyan
    } catch {
        Write-Warning "Failed to disable task $task : $($_.Exception.Message)"
    }
}
# --- Restart Explorer ---
Stop-Process -Name explorer -Force
Start-Sleep -Seconds 2
Start-Process explorer
Write-Host "Tweaks Applied Successfully!" -ForegroundColor Green