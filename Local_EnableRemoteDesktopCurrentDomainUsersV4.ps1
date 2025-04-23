# =============================
# Enhanced RDP Enablement Script
# Supports both Domain and Non-Domain scenarios
# Includes audit logging and safe operations
# =============================

# Define the log path
$logPath = "$env:ProgramData\RDPSetupLog.txt"
Start-Transcript -Path $logPath -Append

# Enable WOL on all physical Ethernet and Wi-Fi adapters

# Get all enabled physical network adapters
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    $name = $adapter.Name
    Write-Host "`nConfiguring WOL for adapter: $name"

    # Enable 'Wake on Magic Packet'
    try {
        powercfg -devicequery wake_from_any | ForEach-Object {
            if ($_ -eq $name) {
                powercfg -deviceenablewake "$name"
                Write-Host "Enabled 'Allow this device to wake the computer' for $name"
            }
        }
    } catch {
        Write-Warning "Failed to enable device wake for $name. Error: $_"
    }

    # Set advanced WOL settings via registry (if needed)
    # Registry keys differ slightly across vendors (Realtek, Intel, Broadcom etc.)

    $adapterPNPId = (Get-PnpDevice | Where-Object { $_.FriendlyName -eq $name }).InstanceId
    if ($adapterPNPId) {
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Enum\$adapterPNPId\Device Parameters\WakeUp"
        try {
            if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$adapterPNPId") {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$adapterPNPId\Device Parameters" `
                    -Name "WakeOnMagicPacket" -Value 1 -Force -ErrorAction SilentlyContinue
                Write-Host "Set WakeOnMagicPacket registry key for $name"
            }
        } catch {
            Write-Warning "Could not modify registry WOL settings for $name. Error: $_"
        }
    }
}

Write-Host "`nWake-on-LAN configuration completed for all active physical adapters."

Write-Host "`n--- Enabling PowerShell Remoting and Remote Management ---"

# 1. Enable WinRM (PowerShell Remoting)
try {
    Enable-PSRemoting -Force
    Write-Host "PowerShell Remoting (WinRM) enabled."
} catch {
    Write-Warning "Failed to enable PS Remoting: $_"
}

# 2. Set WinRM to start automatically
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

# 3. Enable Firewall rules for WinRM and Remote Management
$firewallRules = @(
    "Windows Remote Management (HTTP-In)",
    "Windows Management Instrumentation (WMI-In)",
    "Remote Event Log Management",
    "Remote Scheduled Tasks Management",
    "Remote Service Management",
    "Remote Volume Management",
    "File and Printer Sharing"
)
foreach ($rule in $firewallRules) {
    Enable-NetFirewallRule -DisplayGroup $rule -ErrorAction SilentlyContinue
}
Write-Host "Firewall rules for WinRM and remote management enabled."

# 4. If in a WORKGROUP, configure TrustedHosts for remoting
$computerSys = Get-WmiObject -Class Win32_ComputerSystem
if (-not $computerSys.PartOfDomain) {
    try {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Write-Host "TrustedHosts set to '*' for workgroup remoting."
    } catch {
        Write-Warning "Failed to set TrustedHosts. Error: $_"
    }
}

# 5. Enable DCOM for MMC tools (optional)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "Y"
Write-Host "DCOM enabled for MMC-based remote management."

# 6. Optional: Add local firewall rule for SMB (needed for event logs, services, etc.)
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

function Add-IfNotExists {
    param (
        [string]$Group,
        [string]$Member
    )
    try {
        $existing = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Member }
        if (-not $existing) {
            Add-LocalGroupMember -Group $Group -Member $Member
            Write-Host "Added '$Member' to '$Group'."
        } else {
            Write-Host "'$Member' is already in '$Group'."
        }
    } catch {
        Write-Error "Error while checking or adding '$Member' to '$Group': $_"
    }
}

try {
    # Step 1: Enable RDP if not already enabled
    $rdpSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    if ($rdpSetting.fDenyTSConnections -ne 0) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Write-Host "Remote Desktop enabled."
    } else {
        Write-Host "Remote Desktop already enabled."
    }

    # Step 2: Enable firewall rules
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Remote Desktop firewall rules enabled."

    # Step 3: Detect domain
    $computerSys = Get-WmiObject -Class Win32_ComputerSystem
    $isDomainJoined = $computerSys.PartOfDomain

    
function Get-OrgSelection {
    param (
        [string[]]$Choices
    )

    if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
        # GUI selection using Out-GridView (arrow keys, mouse supported)
        $selection = $Choices | Out-GridView -Title "Select Organization" -OutputMode Single
    }

    if (-not $selection) {
        # CLI fallback using numbered prompt
        $index = $Host.UI.PromptForChoice("Workgroup Detected", "Select the organization this machine belongs to:", $Choices, 0)
        $selection = $Choices[$index]
    }

    return $selection
}

if (-not $isDomainJoined) {
    Write-Host "This computer is not domain joined."

    $choices = @("A", "B", "C", "D")
    $location = Get-OrgSelection -Choices $choices

    # Map org to SID
    $sidMap = @{
        "a"     = "S-1-5-21-2222222222-3333333333-4444444444-513"
        "B"  = "S-1-5-21-2222222222-3333333333-4444444444-513"  # Replace with actual
        "C"   = "S-1-5-21-5555555555-6666666666-7777777777-513"  # Replace with actual
        "C" = "S-1-5-21-8888888888-9999999999-0000000000-513"  # Replace with actual
    }

    $sid = $sidMap[$location.ToLower()]

    if ($sid) {
        Write-Host "Using SID: $sid"
        & net localgroup "Remote Desktop Users" /add $sid
        Write-Host "Added SID [$sid] to 'Remote Desktop Users'."
    } else {
        Write-Warning "SID not found for selection [$location]. Exiting."
        exit 1
    }
}
ement Script
# Supports both Domain and Non-Domain scenarios
# Includes audit logging and safe operations
# =============================

# Define the log path
$logPath = "$env:ProgramData\RDPSetupLog.txt"
Start-Transcript -Path $logPath -Append

# Enable WOL on all physical Ethernet and Wi-Fi adapters

# Get all enabled physical network adapters
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $adapters) {
    $name = $adapter.Name
    Write-Host "`nConfiguring WOL for adapter: $name"

    # Enable 'Wake on Magic Packet'
    try {
        powercfg -devicequery wake_from_any | ForEach-Object {
            if ($_ -eq $name) {
                powercfg -deviceenablewake "$name"
                Write-Host "Enabled 'Allow this device to wake the computer' for $name"
            }
        }
    } catch {
        Write-Warning "Failed to enable device wake for $name. Error: $_"
    }

    # Set advanced WOL settings via registry (if needed)
    # Registry keys differ slightly across vendors (Realtek, Intel, Broadcom etc.)

    $adapterPNPId = (Get-PnpDevice | Where-Object { $_.FriendlyName -eq $name }).InstanceId
    if ($adapterPNPId) {
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Enum\$adapterPNPId\Device Parameters\WakeUp"
        try {
            if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$adapterPNPId") {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$adapterPNPId\Device Parameters" `
                    -Name "WakeOnMagicPacket" -Value 1 -Force -ErrorAction SilentlyContinue
                Write-Host "Set WakeOnMagicPacket registry key for $name"
            }
        } catch {
            Write-Warning "Could not modify registry WOL settings for $name. Error: $_"
        }
    }
}

Write-Host "`nWake-on-LAN configuration completed for all active physical adapters."

Write-Host "`n--- Enabling PowerShell Remoting and Remote Management ---"

# 1. Enable WinRM (PowerShell Remoting)
try {
    Enable-PSRemoting -Force
    Write-Host "PowerShell Remoting (WinRM) enabled."
} catch {
    Write-Warning "Failed to enable PS Remoting: $_"
}

# 2. Set WinRM to start automatically
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

# 3. Enable Firewall rules for WinRM and Remote Management
$firewallRules = @(
    "Windows Remote Management (HTTP-In)",
    "Windows Management Instrumentation (WMI-In)",
    "Remote Event Log Management",
    "Remote Scheduled Tasks Management",
    "Remote Service Management",
    "Remote Volume Management",
    "File and Printer Sharing"
)
foreach ($rule in $firewallRules) {
    Enable-NetFirewallRule -DisplayGroup $rule -ErrorAction SilentlyContinue
}
Write-Host "Firewall rules for WinRM and remote management enabled."

# 4. If in a WORKGROUP, configure TrustedHosts for remoting
$computerSys = Get-WmiObject -Class Win32_ComputerSystem
if (-not $computerSys.PartOfDomain) {
    try {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Write-Host "TrustedHosts set to '*' for workgroup remoting."
    } catch {
        Write-Warning "Failed to set TrustedHosts. Error: $_"
    }
}

# 5. Enable DCOM for MMC tools (optional)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "Y"
Write-Host "DCOM enabled for MMC-based remote management."

# 6. Optional: Add local firewall rule for SMB (needed for event logs, services, etc.)
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

function Add-IfNotExists {
    param (
        [string]$Group,
        [string]$Member
    )
    try {
        $existing = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Member }
        if (-not $existing) {
            Add-LocalGroupMember -Group $Group -Member $Member
            Write-Host "Added '$Member' to '$Group'."
        } else {
            Write-Host "'$Member' is already in '$Group'."
        }
    } catch {
        Write-Error "Error while checking or adding '$Member' to '$Group': $_"
    }
}

try {
    # Step 1: Enable RDP if not already enabled
    $rdpSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    if ($rdpSetting.fDenyTSConnections -ne 0) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Write-Host "Remote Desktop enabled."
    } else {
        Write-Host "Remote Desktop already enabled."
    }

    # Step 2: Enable firewall rules
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Remote Desktop firewall rules enabled."

    # Step 3: Detect domain
    $computerSys = Get-WmiObject -Class Win32_ComputerSystem
    $isDomainJoined = $computerSys.PartOfDomain

    if (-not $isDomainJoined) {
        Write-Host "This computer is not domain joined."

        # Prompt for known org
        $choices = @("Sarpy", "Bellevue", "LaVista", "Papillion")
        $orgIndex = $Host.UI.PromptForChoice("Workgroup Detected", "Select the organization this machine belongs to:", $choices, 0)
        $location = $choices[$orgIndex]

        # Map org to SID
        $sid = switch ($location.ToLower()) {
            "sarpy"     { "S-1-5-21-1339295860-1783322236-931750244-513" }
            "bellevue"  { "S-1-5-21-2709975421-387877448-3719973535-513" }
            "lavista"   { "S-1-5-21-1867141809-1711754803-782984527-513" }
            "papillion" { "S-1-5-21-1927295388-899035431-1232828436-513" }
            default     { "" }
        }

        if ($sid) {
            Write-Host "Using SID: $sid"
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $sid
			$SGroup = New-Object System.Security.Principal.SecurityIdentifier($sid)
			$ResolvedName = $SGroup.Translate([System.Security.Principal.NTAccount]).Value
			if ($ResolvedName) {
				net localgroup "Remote Desktop Users" /add $ResolvedName
			}
            Write-Host "Added SID [$sid] to 'Remote Desktop Users'."
        } else {
            Write-Warning "Unrecognized location or missing SID. Exiting script."
            exit 1
        }
    }
    else {
        $domain = $computerSys.Domain
        $domainGroup = "$domain\Domain Users"
        Write-Host "Domain detected: $domain"

        # Add domain users to RDP group
        Add-IfNotExists -Group "Remote Desktop Users" -Member $domainGroup
    }

    # Step 4: Optional Restart Prompt
    $restart = Read-Host "Changes applied. Do you want to restart now? (Y/N)"
    if ($restart -match "^[Yy]") {
        Write-Host "Restarting system..."
        Restart-Computer -Force
    } else {
        Write-Host "Restart skipped. Some changes may not apply until reboot."
    }
}
catch {
    Write-Error "An unexpected error occurred: $_"
}
finally {
    Stop-Transcript
}