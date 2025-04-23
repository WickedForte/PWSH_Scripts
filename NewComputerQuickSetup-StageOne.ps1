#https://aka.ms/install-powershell.ps1
#https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4
### Acording to this Winget is the best method but if Winget isn't an option there is this script https://aka.ms/install-powershell.ps1 and this one that utilizes this on all OSes.
#https://github.com/fleschutz/PowerShell/blob/main/scripts/install-powershell.ps1
#Invoke-Expression "& { $(Invoke-RestMethod 'https://raw.githubusercontent.com/fleschutz/PowerShell/main/scripts/install-powershell.ps1') } -daily"
#Invoke-Expression "& { $(Invoke-RestMethod 'https://raw.githubusercontent.com/fleschutz/PowerShell/main/scripts/install-powershell.ps1') } -daily"
#Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fleschutz/PowerShell/main/scripts/install-powershell.ps1" -OutFile "$env:Onedrive\Code\Powershell\Initialize-Windows-NewMachineSetup\install-powershell.ps1"
#C:\Users\Spork\OneDrive\Code\Powershell\Initialize-Windows-NewMachineSetup
#Invoke-Expression "& { $(Invoke-RestMethod 'https://aka.ms/install-powershell.ps1') } -useLatest"
# The following one appears to install into the appdata which is less than ideal for an user
#powershell -ExecutionPolicy Bypass -File "C:\Users\Spork\OneDrive\Code\Powershell\Initialize-Windows-NewMachineSetup\install-powershellMicrosoft.ps1"

# Windows Activation Can bypass, Change windows edition, Activate Office, Etcwin
#irm https://get.activated.win | iex
#irm https://massgrave.dev/get | iex

## Software Install Portion ##
#Install Notepad++
Start-Process powershell "C:\Users\Spork\OneDrive\Code\Powershell\Local_SW\SW_Local_Notepad++V2.ps1" -Wait
#Install Winget on Windows 10/11 and forcefully incase AppInstaller.appx is not installed on OS from a custom .WISM image
Start-Process powershell "C:\Users\Spork\OneDrive\Code\Powershell\Local_SW\SW_Local_WingetDesktopAppInstallerInstallFromGitHub.ps1" -Wait
#Install Microsoft PowerToys (MUCH NEEDED!) via Winget
Start-Process winget -ArgumentList 'install', '--id', 'Microsoft.PowerToys', '-e', '--silent' -Wait
    #winget install --id Microsoft.PowerToys -e --silent
    start powertoys
#Install Chocolately
Start-Process powershell "C:\Users\Spork\OneDrive\Code\Powershell\DemoGrounds\ChocolateyWGui-InstallOrUpgrade.ps1" -Wait
#Install UniGetUI (Formerly WingetUI)
Start-Process powershell "C:\Users\Spork\OneDrive\Code\Powershell\Initialize-Windows-NewMachineSetup\Local-SW Install-UnigetGUIWingetUI-GitHub Install.ps1" -Wait
    # Install Scoop from UniGetUI/Winget Install like a subtask
    Start-Process "C:\Program Files\WingetUI\Assets\Utilities\install_scoop.cmd" -ArgumentList "/c" -Wait
# Install KeePassXC via Winget     
Start-Process winget -ArgumentList "install --exact --id KeePassXCTeam.KeePassXC --accept-package-agreements --accept-source-agreements --silent" -Wait
# Install Google Drive via Winget
Start-Process winget -ArgumentList "install --exact --id Google.GoogleDrive --accept-package-agreements --accept-source-agreements --silent" -Wait
# Install Apple iCloud via Winget                                                   
Start-Process winget -ArgumentList "install --exact --id Apple.iCloud --accept-package-agreements --accept-source-agreements --silent" -Wait
# Install Apple iTunes via Winget                           
Start-Process winget -ArgumentList "install --exact --id Apple.iTunes --accept-package-agreements --accept-source-agreements --silent" -Wait
# Install Apple Devices Management
Start-Process winget -ArgumentList 'install --id "9NP83LWLPZ9K" --exact --source msstore --accept-source-agreements --disable-interactivity --silent --accept-package-agreements --force' -Wait

#Thunderbolt Software
# https://apps.microsoft.com/detail/9n6f0jv38ph1?rtc=1&hl=en-US&gl=US
#Intel Unison 
# https://apps.microsoft.com/detail/9pp9gzm2gn26?hl=en-us&gl=US

##Install PC Game Clients
#Install Valve Steam with Winget but through a Powershell object and Silent and Location arguments
Start-Process winget -ArgumentList "install --exact --id Valve.Steam --accept-package-agreements --accept-source-agreements --location C:\Games\Steam --silent" -Wait
    #Install Valve Steam with Winget Silent and Location specification
    #winget install --exact --id Valve.Steam --accept-package-agreements --accept-source-agreements --location C:\Games\Steam --silent
    #Install Valve Steam with Powershell
    #Start-Process -FilePath (Invoke-WebRequest -Uri "https://steamcdn-a.akamaihd.net/client/installer/SteamSetup.exe" -OutFile "$env:USERPROFILE\Downloads\SteamSetup.exe"; "$env:USERPROFILE\Downloads\SteamSetup.exe") -ArgumentList "/S"

# Install Blizzard Battle.Net Games Client
Start-Process winget -ArgumentList "install --exact --id XPDM5VSMTKQLBJ --accept-package-agreements --accept-source-agreements --location C:\Games\EpicGamesLancher --silent" -Wait

# Install EPIC GAMES Launcher
Start-Process winget -ArgumentList "install --exact --id EpicGames.EpicGamesLauncher --accept-package-agreements --accept-source-agreements --location C:\Games\EpicGamesLancher --silent" -Wait

# Install Humble Bundle Humble App
Start-Process winget -ArgumentList "install --exact --id HumbleBundle.HumbleApp --accept-package-agreements --accept-source-agreements --location C:\Games\HumbleBundleHumbleApp --silent" -Wait

# Install League of Legends via Winget League of Legends (North America server)       RiotGames.LeagueOfLegends.NA 
Start-Process winget -ArgumentList "install --exact --id RiotGames.LeagueOfLegends.NA --accept-package-agreements --accept-source-agreements --location C:\Games --silent" -Wait
Stop-Process -name "Riot*" -Force

## Video Game Utilities
# PC Voice Chat
Start-Process winget -ArgumentList "install --exact --id Discord.Discord --accept-package-agreements --accept-source-agreements --location C:\Games\Utilities\Discord --silent" -Wait


## Console Video Game Utilities
## Nintendo
    ## Nintendo Switch
    #TegraRcmGUI Switch RCM ShortFuse to Boot FuseGulee
    Start-Process winget -ArgumentList "install --exact --id eliboa.TegraRcmGUI --accept-package-agreements --accept-source-agreements --location C:\Games\Console\Nintendo\Switch\Utilities\ --silent" -Wait

                                   