#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys Sysmon + Wazuh Agent on a corporate Windows laptop.
    This is what runs on EVERY ENDPOINT (laptop/workstation).

.DESCRIPTION
    This script:
    1. Downloads and installs Sysmon with APT-optimized configuration
    2. Configures Windows audit policies for security event logging
    3. Downloads and installs Wazuh Agent pointed at the central server
    4. Configures the agent with PII anonymization rules
    5. Starts all services

.PARAMETER ServerIP
    IP address or hostname of the central Wazuh Manager server.

.PARAMETER ServerPort
    Wazuh Manager agent communication port (default: 1514).

.PARAMETER AgentGroup
    Wazuh agent group for policy assignment (default: "default").

.PARAMETER RegistrationPassword
    Password for agent registration with the Wazuh Manager.

.EXAMPLE
    .\deploy_endpoint.ps1 -ServerIP "192.168.1.100" -RegistrationPassword "MySecretPass"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,

    [int]$ServerPort = 1514,

    [string]$AgentGroup = "default",

    [Parameter(Mandatory=$true)]
    [string]$RegistrationPassword
)

$ErrorActionPreference = "Stop"
$TempDir = "$env:TEMP\threat-platform-deploy"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  APT Detection Platform — Endpoint Deployment" -ForegroundColor Cyan
Write-Host "  Central Server: $ServerIP:$ServerPort" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────
# STEP 1: Install Sysmon with APT-optimized config
# ──────────────────────────────────────────────────────
Write-Host "`n[1/4] Installing Sysmon..." -ForegroundColor Yellow

$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonZip = "$TempDir\Sysmon.zip"
$SysmonDir = "$TempDir\Sysmon"

# Download Sysmon
if (-not (Test-Path "$SysmonDir\Sysmon64.exe")) {
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZip
    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
}

# Write Sysmon configuration optimized for APT detection
# This config is placed next to this script as sysmon_config.xml
$SysmonConfigPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "sysmon_config.xml"
if (-not (Test-Path $SysmonConfigPath)) {
    Write-Host "  ERROR: sysmon_config.xml not found next to this script!" -ForegroundColor Red
    Write-Host "  Expected at: $SysmonConfigPath" -ForegroundColor Red
    exit 1
}

# Install Sysmon (or update config if already installed)
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($SysmonService) {
    Write-Host "  Sysmon already installed — updating config..." -ForegroundColor Green
    & "$SysmonDir\Sysmon64.exe" -c $SysmonConfigPath 2>&1 | Out-Null
} else {
    Write-Host "  Installing Sysmon64..." -ForegroundColor Green
    & "$SysmonDir\Sysmon64.exe" -accepteula -i $SysmonConfigPath 2>&1 | Out-Null
}
Write-Host "  Sysmon installed and configured." -ForegroundColor Green

# ──────────────────────────────────────────────────────
# STEP 2: Configure Windows audit policies
# ──────────────────────────────────────────────────────
Write-Host "`n[2/4] Configuring Windows audit policies..." -ForegroundColor Yellow

# Enable detailed security auditing for lateral movement detection
$AuditPolicies = @(
    @{ Subcategory = "Logon";                     Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Logoff";                    Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Special Logon";             Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Credential Validation";     Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Process Creation";          Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "disable" }
)

foreach ($policy in $AuditPolicies) {
    auditpol /set /subcategory:"$($policy.Subcategory)" /success:$($policy.Success) /failure:$($policy.Failure) 2>&1 | Out-Null
}

# Enable PowerShell ScriptBlock logging (Event ID 4104)
$PSLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $PSLogPath)) {
    New-Item -Path $PSLogPath -Force | Out-Null
}
Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockLogging" -Value 1

# Enable command-line auditing in process creation events
$CmdLinePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $CmdLinePath)) {
    New-Item -Path $CmdLinePath -Force | Out-Null
}
Set-ItemProperty -Path $CmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

Write-Host "  Audit policies configured." -ForegroundColor Green

# ──────────────────────────────────────────────────────
# STEP 3: Install Wazuh Agent
# ──────────────────────────────────────────────────────
Write-Host "`n[3/4] Installing Wazuh Agent..." -ForegroundColor Yellow

$WazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $WazuhService) {
    $WazuhVersion = "4.7.0"
    $WazuhMsi = "$TempDir\wazuh-agent-$WazuhVersion-1.msi"
    $WazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"

    if (-not (Test-Path $WazuhMsi)) {
        Write-Host "  Downloading Wazuh Agent $WazuhVersion..." -ForegroundColor Green
        Invoke-WebRequest -Uri $WazuhUrl -OutFile $WazuhMsi
    }

    Write-Host "  Installing Wazuh Agent..." -ForegroundColor Green
    Start-Process msiexec.exe -ArgumentList @(
        "/i", $WazuhMsi,
        "/q",
        "WAZUH_MANAGER=$ServerIP",
        "WAZUH_MANAGER_PORT=$ServerPort",
        "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword",
        "WAZUH_AGENT_GROUP=$AgentGroup"
    ) -Wait -NoNewWindow
} else {
    Write-Host "  Wazuh Agent already installed." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────
# STEP 4: Configure Wazuh Agent (ossec.conf)
# ──────────────────────────────────────────────────────
Write-Host "`n[4/4] Configuring Wazuh Agent..." -ForegroundColor Yellow

$OssecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Write the agent configuration
$AgentConfig = @"
<ossec_config>
  <!-- ══ SERVER CONNECTION ══ -->
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
    <!-- Send events every 10 seconds (near-real-time) -->
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>

  <!-- ══ SYSMON EVENT COLLECTION ══ -->
  <!-- This is the PRIMARY telemetry for APT detection -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
    <!-- Collect ALL Sysmon events — filtering done server-side -->
  </localfile>

  <!-- ══ WINDOWS SECURITY LOG ══ -->
  <!-- Authentication events for lateral movement detection -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>
      <!-- Only collect security-relevant events, not everything -->
      <QueryList>
        <Query Id="0">
          <Select Path="Security">
            *[System[(EventID=4624 or EventID=4625 or EventID=4648 or
                      EventID=4672 or EventID=4768 or EventID=4769 or
                      EventID=4776 or EventID=4728 or EventID=4732 or
                      EventID=4698 or EventID=4657 or EventID=4673)]]
          </Select>
        </Query>
      </QueryList>
    </query>
  </localfile>

  <!-- ══ POWERSHELL LOGS ══ -->
  <!-- Detect encoded commands, suspicious scripts -->
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

  <!-- ══ SYSTEM LOG ══ -->
  <!-- Service installations, driver loads -->
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

  <!-- ══ FILE INTEGRITY MONITORING ══ -->
  <!-- Detect changes to critical system files -->
  <syscheck>
    <frequency>600</frequency>
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\SysWOW64</directories>
    <!-- Ignore noisy files -->
    <ignore>C:\Windows\System32\LogFiles</ignore>
    <ignore>C:\Windows\System32\wbem\Logs</ignore>
  </syscheck>

  <!-- ══ ACTIVE RESPONSE (disabled — out of scope for FYP) ══ -->
  <active-response>
    <disabled>yes</disabled>
  </active-response>

  <!-- ══ LOGGING ══ -->
  <logging>
    <log_format>json</log_format>
  </logging>
</ossec_config>
"@

Set-Content -Path $OssecConf -Value $AgentConfig -Encoding UTF8

# Write registration password
$AuthPassPath = "C:\Program Files (x86)\ossec-agent\etc\authd.pass"
Set-Content -Path $AuthPassPath -Value $RegistrationPassword -NoNewline

# Start Wazuh Agent service
Write-Host "  Starting Wazuh Agent service..." -ForegroundColor Green
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Set-Service -Name "WazuhSvc" -StartupType Automatic

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Deployment complete!" -ForegroundColor Green
Write-Host "  Sysmon: Running (check Event Viewer > Microsoft-Windows-Sysmon/Operational)" -ForegroundColor Green
Write-Host "  Wazuh Agent: Connecting to $ServerIP:$ServerPort" -ForegroundColor Green
Write-Host "  Agent Name: $($env:COMPUTERNAME)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`n  Verify agent is connected:" -ForegroundColor Yellow
Write-Host "    On server: docker exec wazuh-manager /var/ossec/bin/agent_control -l" -ForegroundColor White
