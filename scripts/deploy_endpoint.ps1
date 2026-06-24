#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys Sysmon + Wazuh Agent on a corporate Windows endpoint.
    Runs once; Sysmon and Wazuh Agent services then run continuously in the background.

.DESCRIPTION
    Steps performed:
      1. Install/update Sysmon with profile-specific APT-optimized configuration
      2. Configure Windows audit policies (authentication, account management, process)
      3. Enable additional Windows diagnostic logs (DNS Client, WMI, Defender, Firewall)
      4. Install Wazuh Agent and configure event collection + shipping to central server
      5. Verify services are running

    Profiles:
      Lean     - minimum overhead (~0.3% CPU, ~12MB RAM above baseline).
                 Collects: process creation, lateral-movement network ports,
                 LSASS access, Run-key registry, DNS queries.
      Balanced - good coverage with manageable overhead
                 (~1-3% CPU, ~40MB RAM above baseline).
                 Adds: image loads, remote threads, file creates, WMI events,
                 named pipes, account management, Defender/Firewall logs.
      Full     - DEFAULT. Maximum telemetry; matches the feature schema the
                 platform's detectors are trained on. Required for the
                 credential-lateral-movement and DNS-exfil detectors to
                 perform at their published accuracy.
                 Adds: scheduled FIM on sensitive paths, shorter poll interval.

.PARAMETER ServerIP
    IP address or hostname of the central Wazuh Manager server. Required.

.PARAMETER RegistrationPassword
    Password for Wazuh agent registration. Required.

.PARAMETER ServerPort
    Wazuh Manager agent communication port. Default: 1514.

.PARAMETER AgentGroup
    Wazuh agent group for policy assignment. Default: "default".

.PARAMETER Profile
    Resource/coverage profile. Values: Lean | Balanced | Full. Default: Full
    (matches the detectors' trained feature schema).

.PARAMETER WazuhMsiUrl
    URL the script fetches the Wazuh agent MSI from. Defaults to the platform
    API server's cached copy (./install/wazuh-agent.msi) when PlatformApiUrl is
    provided, otherwise to packages.wazuh.com. Override to point at a local
    network mirror.

.PARAMETER SysmonZipUrl
    URL the script fetches Sysmon.zip from. Defaults to the platform API
    server's cached copy, otherwise to download.sysinternals.com.

.PARAMETER WazuhVersion
    Wazuh Agent version to install. Default: 4.7.0.

.PARAMETER Verify
    If specified: check service status only, do not install anything.

.EXAMPLE
    .\deploy_endpoint.ps1 -ServerIP "192.168.1.100" -RegistrationPassword "P@ss!" -Profile Lean
    .\deploy_endpoint.ps1 -ServerIP "192.168.1.100" -RegistrationPassword "P@ss!"
    .\deploy_endpoint.ps1 -ServerIP "192.168.1.100" -RegistrationPassword "P@ss!" -Verify
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIP,

    [Parameter(Mandatory = $true)]
    [string]$RegistrationPassword,

    [int]$ServerPort = 1514,

    [string]$AgentGroup = "default",

    [ValidateSet("Lean", "Balanced", "Full")]
    [string]$Profile = "Full",

    [string]$WazuhVersion = "4.7.0",

    # Remote-control: enrol with AI Platform, install command-handler task.
    # Both must be supplied to enable; otherwise the laptop runs in
    # collection-only mode (no fleet remote control).
    [string]$PlatformApiUrl,        # e.g. https://api.example.com:8000
    [string]$EnrollmentToken,       # X-Enrollment-Token (or legacy bootstrap token)
    [int]$PollIntervalSeconds = 60,

    # Override download URLs -- defaults fall back to the platform server's
    # cached copy when PlatformApiUrl is set, else upstream public URLs.
    [string]$WazuhMsiUrl  = "",
    [string]$SysmonZipUrl = "",

    [switch]$Verify
)

# Default Wazuh/Sysmon download URLs to the platform server's cache when one
# is available. Keeps endpoint installs strictly on-network (Tanzania data
# residency) and removes the dependency on packages.wazuh.com /
# live.sysinternals.com being reachable.
if (-not $WazuhMsiUrl) {
    if ($PlatformApiUrl) {
        $WazuhMsiUrl = "$($PlatformApiUrl.TrimEnd('/'))/install/wazuh-agent.msi"
    } else {
        $WazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
    }
}
if (-not $SysmonZipUrl) {
    if ($PlatformApiUrl) {
        $SysmonZipUrl = "$($PlatformApiUrl.TrimEnd('/'))/install/sysmon.zip"
    } else {
        $SysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    }
}

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path
$TempDir   = "$env:TEMP\threat-platform-deploy"
$WazuhDir  = "C:\Program Files (x86)\ossec-agent"

# -------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------

function Write-Step  { param($n, $total, $msg) Write-Host "`n[$n/$total] $msg" -ForegroundColor Yellow }
function Write-OK    { param($msg) Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  WARN $msg" -ForegroundColor DarkYellow }
function Write-Fail  { param($msg) Write-Host "  FAIL $msg" -ForegroundColor Red }
function Write-Info  { param($msg) Write-Host "       $msg" -ForegroundColor Gray }

function Set-AuditPolicy {
    param([string]$Subcategory, [string]$Success, [string]$Failure)
    $r = Invoke-Native { auditpol /set /subcategory:"$Subcategory" /success:$Success /failure:$Failure }
    if ($r.ExitCode -ne 0) {
        Write-Warn "auditpol failed for '$Subcategory' (may require domain policy override)"
    }
}

function Wait-ServiceStart {
    param([string]$ServiceName, [int]$TimeoutSeconds = 30)
    $end = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $end) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Invoke-Native {
    # Run a native exe without tripping $ErrorActionPreference="Stop" on its
    # benign stderr (banners, EULA acceptance, Sysinternals copyright lines).
    # Caller decides success from $LASTEXITCODE / returned Output.
    param([Parameter(Mandatory)][scriptblock]$Block)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Block 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } finally {
        $ErrorActionPreference = $prev
    }
}

# -------------------------------------------------------------
# VERIFY MODE - just check status, no changes
# -------------------------------------------------------------

if ($Verify) {
    Write-Host "`n=== Endpoint Status Check ===" -ForegroundColor Cyan
    foreach ($svc in @("Sysmon64", "WazuhSvc")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            $color = if ($s.Status -eq "Running") { "Green" } else { "Red" }
            Write-Host "  $svc : $($s.Status)" -ForegroundColor $color
        } else {
            Write-Host "  $svc : NOT INSTALLED" -ForegroundColor Red
        }
    }
    # Check Wazuh agent connectivity (look for recent agent.log entries)
    $agentLog = "$WazuhDir\ossec.log"
    if (Test-Path $agentLog) {
        $connected = Select-String -Path $agentLog -Pattern "Connected to the server" -Quiet
        if ($connected) { Write-OK "Wazuh agent has connected to server" }
        else            { Write-Warn "No recent server connection found in ossec.log" }
    }
    exit 0
}

# -------------------------------------------------------------
# SETUP
# -------------------------------------------------------------

$TotalSteps = if ($PlatformApiUrl -and $EnrollmentToken) { 7 } else { 5 }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host @"

+======================================================+
  APT Detection Platform - Endpoint Deployment
  Server  : $ServerIP`:$ServerPort
  Profile : $Profile
  Host    : $($env:COMPUTERNAME)
+======================================================+
"@ -ForegroundColor Cyan


# -------------------------------------------------------------
# STEP 1: Sysmon
# -------------------------------------------------------------
Write-Step 1 $TotalSteps "Installing / updating Sysmon"

$SysmonZip = "$TempDir\Sysmon.zip"
$SysmonDir = "$TempDir\Sysmon"
$SysmonExe = "$SysmonDir\Sysmon64.exe"

# Select config based on profile
$SysmonConfigName = if ($Profile -eq "Lean") { "sysmon_config_lean.xml" } else { "sysmon_config.xml" }
$SysmonConfigPath = Join-Path $ScriptDir $SysmonConfigName

if (-not (Test-Path $SysmonConfigPath)) {
    Write-Fail "Config file not found: $SysmonConfigPath"
    Write-Info "Expected both 'sysmon_config.xml' and 'sysmon_config_lean.xml' next to this script."
    exit 1
}

if (-not (Test-Path $SysmonExe)) {
    # Standalone-mode shortcut: if Sysmon.zip is bundled alongside this
    # script (the bundle.zip layout), use it directly -- no network round trip.
    $LocalSysmonZip = Join-Path $ScriptDir "Sysmon.zip"
    if (Test-Path $LocalSysmonZip) {
        Write-Info "Using bundled Sysmon.zip from $LocalSysmonZip"
        Copy-Item -Path $LocalSysmonZip -Destination $SysmonZip -Force
        Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
    } else {
        Write-Info "Downloading Sysmon from $SysmonZipUrl"
        try {
            Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZip -UseBasicParsing
            Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
        } catch {
            Write-Fail "Failed to download Sysmon: $_"
            exit 1
        }
    }
}

$SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($SysmonSvc) {
    Write-Info "Sysmon already installed - updating config to $Profile profile..."
    $r = Invoke-Native { & $SysmonExe -c $SysmonConfigPath }
    if ($r.ExitCode -ne 0) {
        Write-Fail "Sysmon config update failed (exit $($r.ExitCode))"
        if ($r.Output) { $r.Output -split "`r?`n" | ForEach-Object { Write-Info $_ } }
        exit 1
    }
    Write-OK "Sysmon config updated ($Profile)"
} else {
    Write-Info "Installing Sysmon64 with $Profile profile..."
    $r = Invoke-Native { & $SysmonExe -accepteula -i $SysmonConfigPath }
    if ($r.ExitCode -ne 0) {
        Write-Fail "Sysmon installation failed (exit $($r.ExitCode))"
        if ($r.Output) { $r.Output -split "`r?`n" | ForEach-Object { Write-Info $_ } }
        exit 1
    }
    Write-OK "Sysmon installed ($Profile)"
}


# -------------------------------------------------------------
# STEP 2: Windows Audit Policies
# -------------------------------------------------------------
Write-Step 2 $TotalSteps "Configuring Windows audit policies"

# Authentication events - core for lateral movement detection
Set-AuditPolicy "Logon"                              "enable"  "enable"
Set-AuditPolicy "Logoff"                             "enable"  "disable"
Set-AuditPolicy "Special Logon"                      "enable"  "disable"
Set-AuditPolicy "Credential Validation"              "enable"  "enable"
Set-AuditPolicy "Kerberos Authentication Service"    "enable"  "enable"
Set-AuditPolicy "Kerberos Service Ticket Operations" "enable"  "enable"

# Process creation - command-line logging for LOLBin detection
Set-AuditPolicy "Process Creation"                   "enable"  "disable"

# Account management - detect persistence via new accounts (T1136)
Set-AuditPolicy "User Account Management"            "enable"  "enable"
Set-AuditPolicy "Security Group Management"          "enable"  "disable"
Set-AuditPolicy "Computer Account Management"        "enable"  "disable"

# Filtering Platform Packet Drop - security signal at low volume (firewall blocks).
# NOTE: Filtering Platform CONNECTION (5156) is intentionally NOT enabled. It fires
# on every successful TCP/UDP flow, generating thousands of events per hour on a
# normal laptop. Sysmon EID 3 already covers lateral-movement port connections.
if ($Profile -eq "Full") {
    Set-AuditPolicy "Filtering Platform Packet Drop" "disable" "enable"
}

# Object Access (Full only) - for SAM database access detection (T1003.002).
# Verbose; only worth it on dedicated SOC endpoints.
if ($Profile -eq "Full") {
    Set-AuditPolicy "SAM"                            "disable" "enable"
    Set-AuditPolicy "Detailed File Share"            "enable"  "disable"
}

# Policy changes - detect audit policy tampering (anti-forensics)
Set-AuditPolicy "Audit Policy Change"                "enable"  "disable"

Write-OK "Audit policies configured"

# Enable PowerShell ScriptBlock logging (Event ID 4104) - detect encoded/obfuscated commands
$PSLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $PSLogPath)) { New-Item -Path $PSLogPath -Force | Out-Null }
Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1
Write-OK "PowerShell ScriptBlock logging enabled (EID 4103/4104)"

# Process command-line inclusion in EID 4688
$CmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $CmdLinePath)) { New-Item -Path $CmdLinePath -Force | Out-Null }
Set-ItemProperty -Path $CmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
Write-OK "Process command-line auditing enabled"

# DNS Client Operational log - provides dns_query_type for ALL queries (incl. NXDOMAIN)
# and TTL for fast-flux detection. High volume (~100-500 evt/min on busy laptops),
# so Lean relies solely on Sysmon EID 22 (which covers query name + type for resolved
# queries via parsed QueryResults).
if ($Profile -ne "Lean") {
    try {
        $dnsLog = Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" -ErrorAction Stop
        if (-not $dnsLog.IsEnabled) {
            $dnsLog.IsEnabled = $true
            $dnsLog.SaveChanges()
            Write-OK "DNS Client Operational log enabled (provides dns_query_type + TTL)"
        } else {
            Write-OK "DNS Client Operational log already enabled"
        }
    } catch {
        Write-Warn "Could not enable DNS Client Operational log: $_"
        Write-Info "dns_query_type still works for resolved queries via Sysmon EID 22"
    }
}

# Enable WMI Activity log - WMI-based lateral movement and persistence
if ($Profile -ne "Lean") {
    try {
        $wmiLog = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction Stop
        if (-not $wmiLog.IsEnabled) {
            $wmiLog.IsEnabled = $true
            $wmiLog.SaveChanges()
            Write-OK "WMI Activity log enabled"
        } else {
            Write-OK "WMI Activity log already enabled"
        }
    } catch {
        Write-Warn "Could not enable WMI Activity log: $_"
    }

    # Enable Task Scheduler Operational log - scheduled task persistence (T1053)
    try {
        $tsLog = Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction Stop
        if (-not $tsLog.IsEnabled) {
            $tsLog.IsEnabled = $true
            $tsLog.SaveChanges()
            Write-OK "Task Scheduler Operational log enabled"
        } else {
            Write-OK "Task Scheduler Operational log already enabled"
        }
    } catch {
        Write-Warn "Could not enable Task Scheduler Operational log: $_"
    }

    # Windows Firewall connection logging.
    # Allowed-connection logging is high volume on a normal laptop (every TCP flow);
    # Balanced logs only DROPS (security signal at low volume).
    # Full logs both for completeness.
    $FwLogDir  = "$env:SystemRoot\System32\LogFiles\Firewall"
    $FwLogFile = "$FwLogDir\pfirewall.log"
    New-Item -ItemType Directory -Path $FwLogDir -Force -ErrorAction SilentlyContinue | Out-Null
    Invoke-Native { netsh advfirewall set allprofiles logging filename $FwLogFile } | Out-Null
    Invoke-Native { netsh advfirewall set allprofiles logging maxfilesize 4096 } | Out-Null
    Invoke-Native { netsh advfirewall set allprofiles logging droppedconnections enable } | Out-Null

    if ($Profile -eq "Full") {
        Invoke-Native { netsh advfirewall set allprofiles logging allowedconnections enable } | Out-Null
        Write-OK "Windows Firewall logging: dropped + allowed -> $FwLogFile"
    } else {
        Invoke-Native { netsh advfirewall set allprofiles logging allowedconnections disable } | Out-Null
        Write-OK "Windows Firewall logging: dropped only -> $FwLogFile"
    }
}


# -------------------------------------------------------------
# STEP 3: Install Wazuh Agent
# -------------------------------------------------------------
Write-Step 3 $TotalSteps "Installing Wazuh Agent $WazuhVersion"

$WazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $WazuhSvc) {
    $WazuhMsi = "$TempDir\wazuh-agent-$WazuhVersion-1.msi"

    if (-not (Test-Path $WazuhMsi)) {
        # Standalone-mode shortcut: bundled MSI next to this script wins.
        $LocalMsi = Join-Path $ScriptDir "wazuh-agent-$WazuhVersion-1.msi"
        if (Test-Path $LocalMsi) {
            Write-Info "Using bundled Wazuh MSI from $LocalMsi"
            Copy-Item -Path $LocalMsi -Destination $WazuhMsi -Force
        } else {
            Write-Info "Downloading Wazuh Agent $WazuhVersion from $WazuhMsiUrl"
            try {
                Invoke-WebRequest -Uri $WazuhMsiUrl -OutFile $WazuhMsi -UseBasicParsing
            } catch {
                Write-Fail "Failed to download Wazuh Agent: $_"
                exit 1
            }
        }
    }

    Write-Info "Running MSI installer (silent)..."
    $msiArgs = @(
        "/i", $WazuhMsi,
        "/qn",
        "WAZUH_MANAGER=$ServerIP",
        "WAZUH_MANAGER_PORT=$ServerPort",
        "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword",
        "WAZUH_AGENT_GROUP=$AgentGroup",
        "WAZUH_AGENT_NAME=$($env:COMPUTERNAME)"
    )
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru
    if ($proc.ExitCode -notin @(0, 3010)) {
        Write-Fail "Wazuh Agent MSI failed (exit $($proc.ExitCode))"
        exit 1
    }
    Write-OK "Wazuh Agent installed"
} else {
    Write-OK "Wazuh Agent already installed (skipping MSI)"
}


# -------------------------------------------------------------
# STEP 4: Configure Wazuh Agent (ossec.conf)
# -------------------------------------------------------------
Write-Step 4 $TotalSteps "Configuring Wazuh Agent ($Profile profile)"

# Profile-specific resource settings
$NotifyTime   = switch ($Profile) { "Lean" { 60 } "Balanced" { 30 } "Full" { 10 } }
$FimFrequency = switch ($Profile) { "Lean" { 86400 } "Balanced" { 43200 } "Full" { 21600 } }
$FimEnabled   = if ($Profile -eq "Lean") { "no" } else { "yes" }
$QueueSize    = switch ($Profile) { "Lean" { 8192 } "Balanced" { 16384 } "Full" { 32768 } }

# Wazuh agent internal_options.conf - controls memory/CPU per profile
$LogcollQueueSize  = switch ($Profile) { "Lean" { 2048 }  "Balanced" { 8192 }  "Full" { 16384 } }
$LogcollMaxLines   = switch ($Profile) { "Lean" { 2000 }  "Balanced" { 5000 }  "Full" { 10000 } }
$LogcollSampleLen  = 256   # cap individual log line length (bytes) - clips runaway events

# 5156/5158 (WFP allowed connection/bind) is intentionally Full-only:
# fires on every TCP/UDP flow -> thousands of events/hour on a normal laptop.
$ExtraSecEvents    = if ($Profile -eq "Full") { " or EventID=5156 or EventID=5158" } else { "" }

# Build ossec.conf content
$AgentConfig = @"
<ossec_config>

  <!-- == SERVER CONNECTION ============================== -->
  <client>
    <server>
      <address>$ServerIP</address>
      <port>$ServerPort</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>$($env:COMPUTERNAME)</agent_name>
      <groups>$AgentGroup</groups>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
    <!-- Profile: $Profile | notify_time controls event send frequency -->
    <notify_time>$NotifyTime</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>

  <!-- == LOCAL EVENT BUFFER ============================== -->
  <!-- queue_size lives here, NOT inside <client>. The Wazuh 4.7 Windows
       agent rejects <queue_size> as an invalid <client> child element
       (error 1230) and refuses to start. -->
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>$QueueSize</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- == SYSMON EVENTS (primary APT telemetry source) ==== -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
    <!-- All Sysmon events - filtering is done in sysmon_config.xml -->
  </localfile>

  <!-- == WINDOWS SECURITY LOG ============================ -->
  <!--
    Events collected:
    4624  Successful logon             -> lateral movement detection
    4625  Failed logon                 -> brute force / credential stuffing
    4648  Explicit credential logon    -> Pass-the-Hash (T1550.002)
    4672  Special privileges logon     -> privilege escalation
    4768  Kerberos TGT request         -> Kerberoasting detection
    4769  Kerberos service ticket req  -> lateral movement via Kerberos
    4776  NTLM authentication          -> Pass-the-Hash (T1550.002)
    4728  Member added to global group -> privilege escalation
    4732  Member added to local group  -> privilege escalation
    4698  Scheduled task created       -> persistence (T1053)
    4657  Registry value modified      -> persistence (backup to EID 13)
    4673  Sensitive privilege use      -> lateral movement prereqs
    4720  User account created         -> persistence (T1136)
    4722  User account enabled         -> persistence
    4724  Password reset attempt       -> credential manipulation
    4725  User account disabled        -> defense evasion / clean-up
    4726  User account deleted         -> clean-up after attack
    4738  User account changed         -> persistence or privilege change
    5156  WFP permitted connection     -> Full profile only (very high volume)
    5158  WFP permitted bind           -> Full profile only
  -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Security">
            *[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4768 or EventID=4769 or EventID=4776 or EventID=4728 or EventID=4732 or EventID=4698 or EventID=4657 or EventID=4673 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4738$ExtraSecEvents)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == POWERSHELL LOGS ================================== -->
  <!-- EID 4103: Module logging | EID 4104: ScriptBlock logging -->
  <!-- Detects encoded commands, Invoke-Expression, AMSI bypass -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-PowerShell/Operational">
            *[System[(EventID=4103 or EventID=4104)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == SYSTEM LOG ======================================= -->
  <!-- EID 7045: New service installed (lateral movement via service creation) -->
  <!-- EID 7040: Service start type changed                                   -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="System">
            *[System[(EventID=7045 or EventID=7040)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

"@

# Balanced/Full: add additional log sources
if ($Profile -ne "Lean") {
    $AgentConfig += @"
  <!-- == DNS CLIENT OPERATIONAL ========================== -->
  <!--
    Supplies dns_query_type for ALL queries (including NXDOMAIN responses
    where Sysmon EID 22 has no QueryResults to parse) and TTL for fast-flux
    detection. High volume - Lean profile relies solely on Sysmon EID 22.

    EID 3006: DNS query initiated
    EID 3008: DNS response received (query type + TTL + response data)
    EID 3020: DNS query completed
  -->
  <localfile>
    <location>Microsoft-Windows-DNS-Client/Operational</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-DNS-Client/Operational">
            *[System[(EventID=3006 or EventID=3008 or EventID=3020)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == WINDOWS DEFENDER OPERATIONAL ==================== -->
  <!--
    Malware detection context: if Defender fires on the same
    endpoint that shows lateral movement indicators, confidence
    score increases significantly.
    EID 1006: Malware detected
    EID 1007: Action taken on malware
    EID 1116: Malware detected (real-time protection)
    EID 1117: Action taken (real-time protection)
    EID 5001: Real-time protection disabled (defense evasion)
  -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-Windows Defender/Operational">
            *[System[(EventID=1006 or EventID=1007 or EventID=1116 or EventID=1117 or EventID=5001)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == WMI ACTIVITY OPERATIONAL ======================== -->
  <!--
    WMI-based lateral movement (T1047) and persistence via
    WMI event subscriptions (T1546.003).
    EID 5857: WMI provider host activity (normal)
    EID 5858: WMI query failure (can indicate reconnaissance)
    EID 5860: Temporary WMI event subscription created
    EID 5861: Permanent WMI event subscription created (persistence!)
  -->
  <localfile>
    <location>Microsoft-Windows-WMI-Activity/Operational</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-WMI-Activity/Operational">
            *[System[(EventID=5857 or EventID=5858 or EventID=5860 or EventID=5861)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == TASK SCHEDULER OPERATIONAL ====================== -->
  <!--
    Scheduled task persistence (T1053.005).
    More granular than Security EID 4698.
    EID 106:  Task registered (created)
    EID 140:  Task registration failed
    EID 141:  Task deleted
    EID 200:  Task action started
    EID 201:  Task action completed
  -->
  <localfile>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
    <log_format>eventchannel</log_format>
    <query>
      <QueryList>
        <Query Id="0">
          <Select Path="Microsoft-Windows-TaskScheduler/Operational">
            *[System[(EventID=106 or EventID=140 or EventID=141)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- == WINDOWS FIREWALL CONNECTION LOG ================ -->
  <!--
    Provides bytes_sent / bytes_received for network connections.
    Used by feature pipeline to compute traffic volume features.
    Enabled in Step 2 via netsh advfirewall.
  -->
  <localfile>
    <location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location>
    <log_format>syslog</log_format>
  </localfile>

"@
}

# File Integrity Monitoring
# NOTE: NEVER use realtime="yes" on System32 - it generates hundreds of events per
# minute from legitimate Windows activity and will exhaust CPU/RAM.
# Use scheduled scans on targeted high-value paths only.
if ($FimEnabled -eq "yes") {
    $AgentConfig += @"
  <!-- == FILE INTEGRITY MONITORING ======================= -->
  <!--
    Scheduled scan (NOT realtime) on targeted paths.
    Profile: $Profile - scan frequency: every $FimFrequency seconds
    Detects: malware drops, credential file theft, config tampering.

    INTENTIONALLY excluded: C:\Windows\System32\ (entire dir) - realtime
    monitoring there generates unmanageable event volume.
  -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>$FimFrequency</frequency>

    <!-- Critical driver and boot files -->
    <directories check_all="yes">C:\Windows\System32\drivers</directories>

    <!-- User profile areas (data staging, malware drops in user space) -->
    <directories check_all="yes" report_changes="yes">C:\Users</directories>

    <!-- Program data (common malware staging location) -->
    <directories check_all="yes">C:\ProgramData</directories>

    <!-- Startup locations (persistence) -->
    <directories check_all="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>

    <!-- Wazuh agent config integrity (detect agent tampering) -->
    <directories check_all="yes">C:\Program Files (x86)\ossec-agent\etc</directories>

    <!-- Ignore high-churn subdirs within monitored paths -->
    <ignore>C:\Users\All Users\Microsoft\Windows\Caches</ignore>
    <ignore>C:\ProgramData\Microsoft\Windows\WER</ignore>
    <ignore type="sregex">.log$|.tmp$|.etl$</ignore>
  </syscheck>

"@
} else {
    $AgentConfig += @"
  <!-- == FILE INTEGRITY MONITORING ======================= -->
  <!-- Disabled in Lean profile to minimise resource usage. -->
  <syscheck>
    <disabled>yes</disabled>
  </syscheck>

"@
}

$AgentConfig += @"
  <!-- == ACTIVE RESPONSE ================================= -->
  <!-- Disabled - out of scope for this FYP deployment.     -->
  <active-response>
    <disabled>yes</disabled>
  </active-response>

  <!-- == AGENT LOGGING ==================================== -->
  <logging>
    <log_format>json</log_format>
  </logging>

</ossec_config>
"@

$OssecConf = "$WazuhDir\ossec.conf"
if (-not (Test-Path $WazuhDir)) {
    Write-Fail "Wazuh install directory not found: $WazuhDir"
    Write-Info "Check that the Wazuh Agent MSI installed successfully."
    exit 1
}

# Write as UTF-8 WITHOUT BOM. PowerShell 5.1's "-Encoding UTF8" emits a BOM,
# and the Wazuh agent's XML parser silently aborts on the leading BOM bytes
# (no log written, service crashes immediately, no Application event log entry).
[System.IO.File]::WriteAllText($OssecConf, $AgentConfig, (New-Object System.Text.UTF8Encoding $false))
Write-OK "ossec.conf written ($Profile profile)"

# Write registration password file
$AuthPassPath = "$WazuhDir\etc\authd.pass"
New-Item -ItemType Directory -Path "$WazuhDir\etc" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Content -Path $AuthPassPath -Value $RegistrationPassword -NoNewline -Encoding ASCII
Write-OK "Registration password written"

# -------------------------------------------------------------
# Wazuh agent internal_options.local.conf - per-profile resource tuning
# Caps memory/CPU used by the logcollector. Default Wazuh settings target
# server-class hosts; defaults on a laptop can spike RAM during event bursts.
# -------------------------------------------------------------
$InternalConf = @"
# Auto-generated by deploy_endpoint.ps1 - profile: $Profile
# Logcollector: caps in-memory event queue and per-cycle read size
logcollector.queue_size=$LogcollQueueSize
logcollector.max_lines=$LogcollMaxLines
logcollector.sample_log_length=$LogcollSampleLen
# Throttle eventchannel polling - lower values = lower CPU spikes
logcollector.remote_commands=0
# Cap agent memory usage by trimming buffered messages
agent.recv_timeout=60
"@
$InternalConfPath = "$WazuhDir\internal_options.local.conf"
Set-Content -Path $InternalConfPath -Value $InternalConf -Encoding ASCII
Write-OK "internal_options.local.conf written (queue=$LogcollQueueSize, max_lines=$LogcollMaxLines)"


# -------------------------------------------------------------
# STEP 5: Start services and verify
# -------------------------------------------------------------
Write-Step 5 $TotalSteps "Starting and verifying services"

# Sysmon - installer sets StartupType=Automatic; we don't call Set-Service
# here because Sysmon hardens its service DACL against Set-Service's implicit
# description-update (would fail with "Access is denied" even as Admin).
$SysmonSvc2 = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($SysmonSvc2 -and $SysmonSvc2.Status -ne "Running") {
    Start-Service -Name "Sysmon64"
}
$sysmonRunning = Wait-ServiceStart "Sysmon64" 15
if ($sysmonRunning) { Write-OK "Sysmon64 running" }
else                { Write-Fail "Sysmon64 did not start - check Event Viewer" ; exit 1 }

# Wazuh Agent (restart to pick up new config)
$wazuhSvc2 = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuhSvc2) {
    if ($wazuhSvc2.Status -eq "Running") {
        Restart-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
    } else {
        Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    }
    Set-Service -Name "WazuhSvc" -StartupType Automatic
    $wazuhRunning = Wait-ServiceStart "WazuhSvc" 30
    if ($wazuhRunning) { Write-OK "WazuhSvc running" }
    else               { Write-Fail "WazuhSvc did not start - check $WazuhDir\ossec.log" ; exit 1 }
} else {
    Write-Fail "WazuhSvc not found after installation"
    exit 1
}


# -------------------------------------------------------------
# STEP 6: Force Windows time sync BEFORE enrollment
# (only runs when we're going to enroll, since auth depends on it)
#
# +==========================================================================+
# |  CLOCK-SKEW SAFETY  --  DO NOT REMOVE / SHORTEN / "SIMPLIFY"              |
# +==========================================================================+
# |  The platform's agent auth is HMAC over (agent_id, unix_ts). The server  |
# |  rejects requests where |server_now - ts| > MAX_AUTH_AGE_SEC (5 min,     |
# |  shared/commands.py). A Windows endpoint whose clock is off by more      |
# |  than 5 min -- VERY common right after a fresh install (random            |
# |  hardware-clock state, no NTP yet, wrong default time zone) -- bricks     |
# |  EVERY agent request including the OTA self-update path. The agent       |
# |  cannot self-heal from a server-bricked auth without going through       |
# |  manual on-host recovery.                                                |
# |                                                                          |
# |  THIS HAS BITTEN US TWICE:                                               |
# |    1. Earlier Get-Date -UFormat %s bug (PS 5.1 returned local-time-as-   |
# |       UTC; fixed in handler's Get-AuthHeader).                           |
# |    2. 2026-05-31 fresh-install incident on DESKTOP-BQKEGGO: endpoint     |
# |       came up with clock 3h behind actual UTC, every poll 401'd.         |
# |                                                                          |
# |  The fix lives in three coordinated places, all required:                |
# |    A. This step (deploy_endpoint.ps1) -- forces NTP sync at install       |
# |    B. agent_command_handler.ps1 -- _TimeSyncIfStale (hourly) AND          |
# |       reactive resync on any 401 (handles drift / suspend / BIOS)        |
# |    C. shared/commands.py near MAX_AUTH_AGE_SEC -- pointer comment         |
# |                                                                          |
# |  DO NOT:                                                                 |
# |    x widen MAX_AUTH_AGE_SEC (weakens replay protection)                  |
# |    x remove this deploy-time /resync (fresh installs would come up       |
# |      with arbitrary hardware-clock offsets)                              |
# |    x remove the MaxPos/NegPhaseCorrection writes -- Windows refuses       |
# |      to STEP a >15min skew without them, leaving the endpoint hours      |
# |      off and quietly stuck                                               |
# |    x remove the platform-server IP from the peer list -- it's the LAN     |
# |      fallback for endpoints that can't reach public NTP                  |
# |                                                                          |
# |  IF you must touch this block, run the verification at the bottom and    |
# |  confirm |endpoint_utc - server_utc| stays <60s through:                 |
# |    1. fresh install on a Windows VM with clock manually set 3h off       |
# |    2. fresh install with no internet (LAN-only)                          |
# |    3. agent restart 24h after install (drift case)                       |
# +==========================================================================+
# -------------------------------------------------------------
if ($PlatformApiUrl -and $EnrollmentToken) {
    Write-Step 6 $TotalSteps "Forcing Windows time sync (HMAC auth depends on this)"

    try {
        # 1. Make sure w32time service exists, is set to auto-start, and is running.
        $w32svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        if ($w32svc) {
            Set-Service -Name w32time -StartupType Automatic -ErrorAction SilentlyContinue
            if ($w32svc.Status -ne 'Running') {
                Start-Service -Name w32time -ErrorAction SilentlyContinue
            }
            Write-OK "Windows Time service ready"
        } else {
            Write-Info "Windows Time service (w32time) not present - skipping"
        }

        # 2. Relax MaxPos/NegPhaseCorrection so w32tm /resync is allowed to STEP
        #    a large delta (default cap is ~15 min; fresh installs are often hours
        #    off). 0xFFFFFFFF = "any positive value, no cap".
        $cfgPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
        if (Test-Path $cfgPath) {
            Set-ItemProperty -Path $cfgPath -Name "MaxPosPhaseCorrection" `
                -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $cfgPath -Name "MaxNegPhaseCorrection" `
                -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
            Write-OK "Relaxed phase-correction caps (large jumps allowed)"
        }

        # 3. Configure peer list. Internet sources first, the platform-server IP
        #    as the LAN fallback for endpoints that can't reach the public NTP
        #    pool (common on locked-down networks).
        $peerList = "time.windows.com,0x9 pool.ntp.org,0x9 $ServerIP,0x9"
        & w32tm /config /manualpeerlist:"$peerList" /syncfromflags:manual `
                /reliable:no /update 2>&1 | Out-Null
        Restart-Service -Name w32time -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # 4. Force a sync. /rediscover re-resolves the peer list (avoids
        #    using a cached failed-peer state). NOTE: w32tm /resync does NOT
        #    accept a /force flag -- the "force a large jump past the default
        #    15-min cap" comes from MaxPos/NegPhaseCorrection registry writes
        #    above, NOT from a CLI flag. Valid: /computer /nowait /rediscover
        #    /soft.
        $resyncOut = & w32tm /resync /rediscover 2>&1
        $resyncMsg = ($resyncOut -join '; ').Trim()
        if ($resyncMsg -match "successfully") {
            Write-OK "Time sync: $resyncMsg"
        } elseif ($resyncMsg -match "(?i)(error|fail)") {
            Write-Info "Time sync attempt: $resyncMsg (handler will retry on next poll)"
        } else {
            Write-Info "Time sync: $resyncMsg"
        }

        # 5. Verify: compare endpoint UTC to the platform server's HTTP Date
        #    header. If the delta still exceeds the HMAC window, warn loudly --
        #    enrollment itself will succeed (admin-token path), but the agent's
        #    first poll will 401 until the clock catches up.
        $deltaSec = $null
        try {
            $hr = Invoke-WebRequest -Uri "$($PlatformApiUrl.TrimEnd('/'))/install/agent_command_handler.ps1" `
                                    -Method Head -TimeoutSec 10 -UseBasicParsing
            $svrDate = $hr.Headers["Date"]
            if ($svrDate) {
                $svrUtc   = [DateTime]::Parse($svrDate).ToUniversalTime()
                $deltaSec = [Math]::Abs(([DateTime]::UtcNow - $svrUtc).TotalSeconds)
                if ($deltaSec -gt 300) {
                    Write-Fail ("Clock still off by {0:N0}s vs server (>{1}s HMAC window). " -f $deltaSec, 300)
                    Write-Fail "Agent auth WILL 401 until clock self-heals. Manually set time then retry, or wait one poll for reactive resync."
                } elseif ($deltaSec -gt 60) {
                    Write-Info ("Clock delta vs server: {0:N0}s (within 5-min HMAC window but noisy)" -f $deltaSec)
                } else {
                    Write-OK ("Clock in sync with server (delta = {0:N0}s)" -f $deltaSec)
                }
            }
        } catch {
            Write-Info "Could not measure clock delta against server: $_"
        }

        # 6. Record the successful sync timestamp so the handler's periodic
        #    _TimeSyncIfStale won't redundantly re-sync on the first poll.
        if (-not (Test-Path "HKLM:\SOFTWARE\APTPlatform")) {
            New-Item -Path "HKLM:\SOFTWARE\APTPlatform" -Force | Out-Null
        }
        if ($null -ne $deltaSec -and $deltaSec -le 300) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" -Name "LastTimeSyncOkAt" `
                -Value ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Info "Time sync step encountered an error: $_ (handler will retry on next poll)"
    }
}

# -------------------------------------------------------------
# STEP 7: Fleet remote-control bootstrap (optional)
# Enroll with AI Platform, store DPAPI-encrypted secret in registry,
# install command-handler scheduled task. Skipped if either of
# -PlatformApiUrl / -EnrollmentToken is missing.
# -------------------------------------------------------------
if ($PlatformApiUrl -and $EnrollmentToken) {
    Write-Step 7 $TotalSteps "Enrolling with AI Platform for remote control"

    $RegBase   = "HKLM:\SOFTWARE\APTPlatform"
    $InstallDir = "$env:ProgramData\APTPlatform"
    if (-not (Test-Path $RegBase))    { New-Item -Path $RegBase -Force | Out-Null }
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

    # 1. Enroll - ask the API for a fresh per-agent secret
    $enrollUrl = "$($PlatformApiUrl.TrimEnd('/'))/fleet/agents/enroll"
    $body = @{ agent_id = $env:COMPUTERNAME; profile = $Profile } | ConvertTo-Json -Compress
    Write-Info "Enrolling at $enrollUrl"
    try {
        # URL-served install flow uses short-lived enrollment tokens via
        # X-Enrollment-Token. Tokens can be single- or multi-use (set on
        # the server when minted) and are dedup'd by agent_id, so re-runs
        # of this one-liner on the same machine do not consume an extra
        # slot -- they just rotate the agent's HMAC secret. Legacy
        # long-lived FLEET_BOOTSTRAP_TOKEN callers can keep using the
        # bootstrap-header path by editing the script -- the server
        # accepts both headers.
        $resp = Invoke-RestMethod -Method Post -Uri $enrollUrl `
            -Headers @{
                "Content-Type"       = "application/json"
                "X-Enrollment-Token" = $EnrollmentToken
            } `
            -Body $body -TimeoutSec 30 -UseBasicParsing
    } catch {
        Write-Fail "Enrollment failed: $_"
        Write-Info "Skipping remote-control setup - endpoint will still collect telemetry."
        $resp = $null
    }

    if ($resp -and $resp.agent_secret) {
        # 2. Encrypt secret with DPAPI (machine scope) and store in registry
        Add-Type -AssemblyName System.Security
        # API returns the secret base64url-encoded (no padding). We need the
        # RAW decoded bytes for HMAC, because the server's get_agent_secret()
        # returns decode_secret(...) which is the raw bytes. Storing ASCII of
        # the base64 string would make HMAC signatures never match the server.
        $b64url = $resp.agent_secret
        $std    = $b64url.Replace('-', '+').Replace('_', '/')
        $pad    = (4 - ($std.Length % 4)) % 4
        if ($pad -gt 0) { $std += ('=' * $pad) }
        $secretBytes = [Convert]::FromBase64String($std)
        $cipher = [System.Security.Cryptography.ProtectedData]::Protect(
            $secretBytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $secretB64 = [Convert]::ToBase64String($cipher)

        Set-ItemProperty -Path $RegBase -Name "AgentId"              -Value $env:COMPUTERNAME
        Set-ItemProperty -Path $RegBase -Name "ServerUrl"            -Value $PlatformApiUrl
        Set-ItemProperty -Path $RegBase -Name "AgentSecret"          -Value $secretB64
        Set-ItemProperty -Path $RegBase -Name "ServerIP"             -Value $ServerIP
        Set-ItemProperty -Path $RegBase -Name "RegistrationPassword" -Value $RegistrationPassword
        Set-ItemProperty -Path $RegBase -Name "Profile"              -Value $Profile
        Set-ItemProperty -Path $RegBase -Name "ScriptDir"            -Value $InstallDir

        # Lock down registry: only SYSTEM + Administrators may read.
        # (Default already restricts non-admin reads, but be explicit on the secret.)
        $acl = Get-Acl $RegBase
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
        $sysRule   = New-Object System.Security.AccessControl.RegistryAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $admRule   = New-Object System.Security.AccessControl.RegistryAccessRule(
            "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($sysRule)
        $acl.AddAccessRule($admRule)
        Set-Acl -Path $RegBase -AclObject $acl
        Write-OK "Agent secret stored (DPAPI-encrypted, SYSTEM/Admin-only)"

        # 3. Copy handler + deploy script into a stable location
        Copy-Item -Path (Join-Path $ScriptDir "agent_command_handler.ps1") `
                  -Destination (Join-Path $InstallDir "agent_command_handler.ps1") -Force
        Copy-Item -Path (Join-Path $ScriptDir "deploy_endpoint.ps1") `
                  -Destination (Join-Path $InstallDir "deploy_endpoint.ps1") -Force
        Copy-Item -Path (Join-Path $ScriptDir "sysmon_config.xml") `
                  -Destination (Join-Path $InstallDir "sysmon_config.xml") -Force
        Copy-Item -Path (Join-Path $ScriptDir "sysmon_config_lean.xml") `
                  -Destination (Join-Path $InstallDir "sysmon_config_lean.xml") -Force
        Set-ItemProperty -Path $RegBase -Name "ScriptDir" -Value $InstallDir
        Write-OK "Handler files copied to $InstallDir"

        # 4. Install (or update) scheduled task
        $taskName = "APTPlatformCommandHandler"
        $handler  = Join-Path $InstallDir "agent_command_handler.ps1"
        $action   = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$handler`""
        $trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30) `
                    -RepetitionInterval (New-TimeSpan -Seconds $PollIntervalSeconds)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
        $settings  = New-ScheduledTaskSettingsSet `
                        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                        -StartWhenAvailable

        # Replace any existing task
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "APT Platform fleet command handler - polls every $PollIntervalSeconds`s" `
            | Out-Null

        Write-OK "Scheduled task '$taskName' installed (every $PollIntervalSeconds`s as SYSTEM)"

        # 5. Trigger immediate first poll for verification
        Start-ScheduledTask -TaskName $taskName
        Write-OK "Triggered first poll - see $InstallDir\handler.log"
    }
}


# -------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------
Write-Host @"

+======================================================+
  Deployment Complete
  Profile  : $Profile
  Server   : $ServerIP`:$ServerPort
  Agent    : $($env:COMPUTERNAME)
+======================================================+
"@ -ForegroundColor Green

Write-Host "  Verify agent connected (run on server):" -ForegroundColor Yellow
Write-Host "    docker exec wazuh-manager /var/ossec/bin/agent_control -l" -ForegroundColor White
Write-Host "`n  Re-check status on this endpoint:" -ForegroundColor Yellow
Write-Host "    .\deploy_endpoint.ps1 -ServerIP $ServerIP -RegistrationPassword *** -Verify" -ForegroundColor White
Write-Host ""
