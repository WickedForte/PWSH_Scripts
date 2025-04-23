# ComprehensiveDebloat.ps1
# This script debloats a fresh Windows 11 install by removing many UWP/Metro apps
# (bloatware) and disables telemetry services and settings.
#
# IMPORTANT: Run this script as an administrator.
# Backup your system and review all changes before running.

# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "You must run this script as Administrator!"
    exit
}

Write-Host "Starting Windows 11 debloat process..." -ForegroundColor Cyan

# List of app patterns to remove.
# This list includes Dell-related apps, telemetry-related packages, Microsoft UWP apps,
# and several third-party apps installed via the Microsoft Store.
$appsToRemove = @(
    "Dell*Support*Assist",                   # Dell Support Assist
    "Dell*Recovery",                         # Dell Recovery
    "*Dell*Support*",                        # Any Dell support-related
    "*Dell*Recovery*",                       # Any Dell recovery-related
	"*Dell*Digital*Delivery*",
	"*Dell*Digital*Delivery*Services*",
	"*Dell*SupportAssit*",
    "*Telemetry*",                           # Anything with telemetry in the name
    "*MicrosoftFamily*",                     # Microsoft Family (if installed as UWP)
    "Microsoft.BingFinance",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingTravel",
    "Microsoft.GamingServices",
    "Microsoft.Messaging",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.MixedReality.Portal",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "*EclipseManager*",
    "*ActiproSoftwareLLC*",
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
    "*Duolingo-LearnLanguagesforFree*",
    "*PandoraMediaInc*",
    "*CandyCrush*",
    "*BubbleWitch3Saga*",
    "*Wunderlist*",
    "*Flipboard*",
    "*Twitter*",
    "*Facebook*",
	"*LinkedIn",
    "*Royal Revolt*",
    "*Sway*",
    "*Speed Test*",
    "*Dolby*",
    "*Viber*",
    "*ACGMediaPlayer*",
    "*Netflix*",
    "*OneCalendar*",
    "*LinkedInforWindows*",
    "*HiddenCityMysteryofShadows*",
    "*Hulu*",
    "*HiddenCity*",
    "*AdobePhotoshopExpress*",
    "*HotspotShieldFreeVPN*",
    "*Microsoft.Advertising.Xaml*",
	"*Xbox*"
)
# Function to remove apps (both installed and provisioned)
function Remove-AppByPattern {
    param ([string]$pattern)

    # Remove installed apps for all users
    $installedApps = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }
    foreach ($app in $installedApps) {
        Write-Host "Attempting to remove App: $($app.Name) - $($app.PackageFullName)" -ForegroundColor Yellow
        try {
            # Primary removal method
            Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            Write-Host "Successfully removed via Remove-AppxPackage: $($app.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "Remove-AppxPackage failed for $($app.Name). Error: $($_.Exception.Message)" -ForegroundColor Red

            # Fallback 1: Attempt WMI uninstall
            Write-Host "Attempting WMI Uninstall for $($app.Name)" -ForegroundColor Yellow
            try {
                $appWmi = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%$($app.Name)%'" -ErrorAction SilentlyContinue
                if ($appWmi) {
                    $appWmi.Uninstall() | Out-Null
                    Write-Host "Successfully removed via WMI: $($app.Name)" -ForegroundColor Green
                } else {
                    Write-Host "WMI could not find the app: $($app.Name)" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "WMI uninstall failed for $($app.Name). Error: $($_.Exception.Message)" -ForegroundColor Red
            }

            # Fallback 2: Registry-based removal (Dell-specific)
            Write-Host "Attempting registry-based removal for Dell apps..." -ForegroundColor Yellow
            try {
                $registryApps = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
                Get-ItemProperty | Where-Object {$_.DisplayName -match $pattern}
                foreach ($appReg in $registryApps) {
                    if ($appReg.UninstallString) {
                        $uninst = $appReg.UninstallString
                        Write-Host "Running uninstall command: $uninst" -ForegroundColor Yellow
                        & cmd /c "$uninst /quiet /norestart"
                        Write-Host "Successfully removed via Registry: $($appReg.DisplayName)" -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Host "Registry removal failed for $($app.Name). Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Remove provisioned apps for future users
    $provApps = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $pattern }
    foreach ($prov in $provApps) {
        Write-Host "Attempting to remove Provisioned App: $($prov.DisplayName)" -ForegroundColor Yellow
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
            Write-Host "Successfully removed provisioned app: $($prov.DisplayName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Remove-AppxProvisionedPackage failed for $($prov.DisplayName). Error: $($_.Exception.Message)" -ForegroundColor Red

            # Fallback logic for provisioned apps (if available)
            Write-Host "No additional methods available for provisioned app: $($prov.DisplayName)" -ForegroundColor Gray
        }
    }
}

# Specialized removal for Dell applications using registry-based methods
function Remove-DellApps {
    Write-Host "Removing Dell preinstalled applications..." -ForegroundColor Cyan

    # Dell-specific removal commands
    #Get-Package -Name "*Dell Command*" | Uninstall-Package -ErrorAction SilentlyContinue
    #Get-Package -Name "*Dell Power Manager Service*" | Uninstall-Package -ErrorAction SilentlyContinue
    #Get-Package -Name "*Dell Digital Delivery Services*" | Uninstall-Package -ErrorAction SilentlyContinue

    # Removing Dell SupportAssist using registry-based logic
    $SAVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty | Where-Object {$_.DisplayName -match "SupportAssist"} | Where-Object {$_.DisplayVersion -notlike "3.2*"} |
    Select-Object -Property DisplayVersion, UninstallString, PSChildName

    foreach ($ver in $SAVer) {
        if ($ver.UninstallString) {
            $uninst = $ver.UninstallString
            Write-Host "Running uninstall command: $uninst" -ForegroundColor Yellow
            & cmd /c "$uninst /quiet /norestart"
            Write-Host "Successfully removed: SupportAssist ($($ver.DisplayVersion))" -ForegroundColor Green
        }
    }

   ## Removing Dell Optimizer
   #$unins = Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
   #Get-ItemProperty | Where-Object {$_.DisplayName -Like "*Dell Optimizer*"} | Select Displayname, Uninstallstring
   #
   #if ($unins.UninstallString) {
   #    Write-Host "Running uninstall command for Dell Optimizer: $($unins.UninstallString)" -ForegroundColor Yellow
   #    & cmd /c "$($unins.UninstallString) /quiet /norestart"
   #    Write-Host "Dell Optimizer removed successfully" -ForegroundColor Green
   #} else {
   #    Write-Host "Dell Optimizer removal failed or is not installed" -ForegroundColor Red
   #}
}

# Main script execution
Remove-DellApps
foreach ($pattern in $appsToRemove) {
    Write-Host "Processing pattern: '$pattern'" -ForegroundColor Cyan
    Remove-AppByPattern -pattern $pattern
}

function Remove-PersistentApp {
    param ([string]$appName)

    Write-Host "Processing persistent app: $appName" -ForegroundColor Cyan

    # Step 1: Remove installed app for all users
    $installedApps = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$appName*" }
    foreach ($app in $installedApps) {
        Write-Host "Attempting to remove App: $($app.Name) - $($app.PackageFullName)" -ForegroundColor Yellow
        try {
            Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            Write-Host "Successfully removed via Remove-AppxPackage: $($app.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove $($app.Name). Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Step 2: Remove provisioned app for future users
    $provApps = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$appName*" }
    foreach ($prov in $provApps) {
        Write-Host "Attempting to remove Provisioned App: $($prov.DisplayName)" -ForegroundColor Yellow
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
            Write-Host "Successfully removed provisioned app: $($prov.DisplayName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove provisioned app $($prov.DisplayName). Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Step 3: Block app from launching using registry modification
    Write-Host "Blocking the app from launching: $appName" -ForegroundColor Cyan
    try {
        $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "AppExecutionAliasRedirects" -Value "{\"$appName.exe\":\"\"}" -Type String -ErrorAction SilentlyContinue
        Write-Host "App blocked from launching via registry modification: $appName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to block the app via registry. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Remove LinkedIn
Remove-PersistentApp -appName "LinkedIn"

# Remove Xbox
Remove-PersistentApp -appName "Xbox"

Write-Host "Persistent app removal process complete. A restart may be required." -ForegroundColor Green

# Process each app removal pattern
foreach ($pattern in $appsToRemove) {
    Write-Host "Processing pattern: '$pattern'" -ForegroundColor Cyan
    Remove-AppByPattern -pattern $pattern
}

Write-Host "Finished removing UWP apps." -ForegroundColor Green

# Disable Telemetry Services
Write-Host "Disabling telemetry services..." -ForegroundColor Cyan
$servicesToDisable = @("DiagTrack", "dmwappushservice")
foreach ($svc in $servicesToDisable) {
    try {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled
            Write-Host "Disabled service: $svc" -ForegroundColor Yellow
        }
        else {
            Write-Host "Service $svc not found." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Error disabling service $svc" -ForegroundColor Red
        Write-Host "Error message: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Disable Game Bar for all users and future users
Write-Host "Disabling Game Bar functionality for all current users, current user, and future users..." -ForegroundColor Cyan

# Disable for all users (Current and Future)
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameBar"  # Future users
)

foreach ($path in $registryPaths) {
    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name Value -Value 0 -Type DWord -Force
        Write-Host "Game Bar disabled for future users using registry path: $path" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error disabling Game Bar at registry path $path" -ForegroundColor Red
        Write-Host "Error message: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Disable for current user
try {
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
    Write-Host "Game Bar disabled for current user" -ForegroundColor Yellow
}
catch {
    Write-Host "Error disabling Game Bar for current user" -ForegroundColor Red
    Write-Host "Error message: $($_.Exception.Message)" -ForegroundColor Red
}

# Disable Recall (if applicable)
Write-Host "Disable Recall functionality is not defined within this script." -ForegroundColor Cyan

Write-Host "Debloat process complete. A restart may be necessary for all changes to take effect." -ForegroundColor Green