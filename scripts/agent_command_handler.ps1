# scripts/agent_command_handler.ps1
# ═══════════════════════════════════════════════════════════════════════════
#   APT Threat Hunting Platform — Agent Command Handler
#
#   Runs as SYSTEM via Task Scheduler every 60 seconds. Polls the AI Platform
#   for pending commands, verifies HMAC signatures, executes WHITELISTED
#   operations, and reports results back.
#
#   Configuration (registry HKLM:\SOFTWARE\APTPlatform):
#     AgentId               — this host's identifier (e.g. computer name)
#     ServerUrl             — base URL of AI Platform API (e.g. https://api:8000)
#     AgentSecret           — base64 of DPAPI-encrypted HMAC secret (machine scope)
#     ServerIP              — Wazuh manager IP (used by SET_PROFILE re-deploy)
#     RegistrationPassword  — used by SET_PROFILE re-deploy
#     Profile               — current profile (Lean|Balanced|Full)
#     ScriptDir             — directory containing deploy_endpoint.ps1
#
#   SECURITY MODEL
#   • Agent secret: never leaves DPAPI-encrypted form on disk.
#   • Every command from server is HMAC-SHA256 signed; we verify before exec.
#   • Replay defense: server includes monotonic sequence + expires_at; we
#     drop expired commands and the server itself drops out-of-window auth.
#   • Whitelist: only command types in $Handlers will execute. Anything else
#     is rejected and reported back as "rejected".
# ═══════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

$RegPath = "HKLM:\SOFTWARE\APTPlatform"
$LogDir  = "$env:ProgramData\APTPlatform"
$LogFile = Join-Path $LogDir "handler.log"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Level, [string]$Msg)
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "$ts [$Level] $Msg" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Get-Setting {
    param([string]$Name, [string]$Default = $null)
    try {
        return (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction Stop).$Name
    } catch {
        if ($null -ne $Default) { return $Default }
        throw "Missing required registry value: $Name"
    }
}

# ── Load configuration ─────────────────────────────────────────────────────

try {
    $AgentId   = Get-Setting "AgentId"
    $ServerUrl = (Get-Setting "ServerUrl").TrimEnd("/")
    $SecretEnc = Get-Setting "AgentSecret"
    $ScriptDir = Get-Setting "ScriptDir" $PSScriptRoot
} catch {
    Write-Log "FATAL" "$_"
    exit 1
}

# ── Decrypt agent secret via DPAPI (machine scope) ─────────────────────────

Add-Type -AssemblyName System.Security
try {
    $cipherBytes = [Convert]::FromBase64String($SecretEnc)
    $secretBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $cipherBytes, $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
} catch {
    Write-Log "FATAL" "Failed to decrypt agent secret: $_"
    exit 1
}

# ── Crypto helpers ─────────────────────────────────────────────────────────

function Get-HmacHex {
    param([byte[]]$Key, [string]$Message)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $hash  = $hmac.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally {
        $hmac.Dispose()
    }
}

function Get-AuthHeader {
    $ts      = [int][double]::Parse((Get-Date -UFormat %s))
    $payload = "{0}:{1}" -f $AgentId, $ts
    $sig     = Get-HmacHex -Key $secretBytes -Message $payload
    return "APT-HMAC agent_id=$AgentId,ts=$ts,sig=$sig"
}

# ── Whitelisted command handlers ───────────────────────────────────────────
# Each handler returns @{ status = "success|failure|rejected"; output = "..." }

function Invoke-SetProfile {
    param($Params)
    $profile = "$($Params.profile)"
    if ($profile -notin @("Lean", "Balanced", "Full")) {
        return @{ status = "rejected"; output = "Invalid profile: $profile" }
    }
    $deploy = Join-Path $ScriptDir "deploy_endpoint.ps1"
    if (-not (Test-Path $deploy)) {
        return @{ status = "failure"; output = "deploy_endpoint.ps1 not found at $deploy" }
    }
    try {
        $serverIP = Get-Setting "ServerIP"
        $regPass  = Get-Setting "RegistrationPassword"
        $output = & $deploy -ServerIP $serverIP -RegistrationPassword $regPass `
                            -Profile $profile 2>&1 | Out-String
        Set-ItemProperty -Path $RegPath -Name "Profile" -Value $profile
        return @{ status = "success"; output = "Profile switched to $profile.`n$($output.Substring(0, [Math]::Min(2048, $output.Length)))" }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

function Invoke-ToggleTelemetry {
    param($Params)
    $source  = "$($Params.source)"
    $enabled = [bool]$Params.enabled
    $valid   = @("sysmon","dns_client","firewall","wmi","defender","tasksched","powershell","fim")
    if ($source -notin $valid) {
        return @{ status = "rejected"; output = "Invalid source: $source" }
    }
    try {
        switch ($source) {
            "sysmon" {
                if ($enabled) { Start-Service Sysmon64 -ErrorAction Stop }
                else          { Stop-Service  Sysmon64 -Force -ErrorAction Stop }
            }
            "dns_client" {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" -ErrorAction Stop
                $log.IsEnabled = $enabled
                $log.SaveChanges()
            }
            "wmi" {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational" -ErrorAction Stop
                $log.IsEnabled = $enabled
                $log.SaveChanges()
            }
            "defender" {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-Windows Defender/Operational" -ErrorAction Stop
                $log.IsEnabled = $enabled
                $log.SaveChanges()
            }
            "tasksched" {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction Stop
                $log.IsEnabled = $enabled
                $log.SaveChanges()
            }
            "powershell" {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction Stop
                $log.IsEnabled = $enabled
                $log.SaveChanges()
            }
            "firewall" {
                $state = if ($enabled) { "enable" } else { "disable" }
                netsh advfirewall set allprofiles logging droppedconnections $state | Out-Null
            }
            "fim" {
                # FIM is owned by Wazuh agent. Toggle the <syscheck><disabled> via
                # a scheduled deploy_endpoint.ps1 re-run? For now: not supported
                # without a profile change.
                return @{ status = "rejected"; output = "FIM toggle requires a profile change (use set_profile)" }
            }
        }
        return @{ status = "success"; output = ("$source " + $(if ($enabled) { "enabled" } else { "disabled" })) }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

function Invoke-RestartServices {
    param($Params)
    $svc = "$($Params.service)"
    try {
        switch ($svc) {
            "wazuh"  { Restart-Service WazuhSvc -Force -ErrorAction Stop }
            "sysmon" { Restart-Service Sysmon64 -Force -ErrorAction Stop }
            "all"    {
                Restart-Service WazuhSvc -Force -ErrorAction Stop
                Restart-Service Sysmon64 -Force -ErrorAction Stop
            }
            default { return @{ status = "rejected"; output = "Invalid service: $svc" } }
        }
        return @{ status = "success"; output = "$svc restarted" }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

function Invoke-GetStatus {
    param($Params)
    $sysmon  = (Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status
    $wazuh   = (Get-Service WazuhSvc  -ErrorAction SilentlyContinue).Status
    $profile = Get-Setting "Profile" "Unknown"
    $info = @{
        agent_id  = $AgentId
        hostname  = $env:COMPUTERNAME
        profile   = "$profile"
        services  = @{ sysmon = "$sysmon"; wazuh = "$wazuh" }
        os        = (Get-CimInstance Win32_OperatingSystem).Caption
        os_build  = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        last_boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")
    }
    return @{ status = "success"; output = (ConvertTo-Json $info -Compress) }
}

function Invoke-UpdateSysmon {
    param($Params)
    $b64 = "$($Params.config_b64)"
    if ([string]::IsNullOrWhiteSpace($b64)) {
        return @{ status = "rejected"; output = "Missing config_b64" }
    }
    try {
        $xml = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
        # Basic sanity check — must contain <Sysmon> root
        if ($xml -notmatch "<Sysmon\s") {
            return @{ status = "rejected"; output = "Payload is not a Sysmon config" }
        }
        $tmp = Join-Path $env:TEMP "sysmon_pushed.xml"
        $xml | Out-File -FilePath $tmp -Encoding utf8
        $sysmonExe = "$env:SystemRoot\Sysmon64.exe"
        if (-not (Test-Path $sysmonExe)) {
            # Fall back to where deploy_endpoint.ps1 cached it
            $sysmonExe = "$env:TEMP\threat-platform-deploy\Sysmon\Sysmon64.exe"
        }
        & $sysmonExe -c $tmp 2>&1 | Out-Null
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        return @{ status = "success"; output = "Sysmon config updated" }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

# ── Dispatch table — WHITELIST ─────────────────────────────────────────────
$Handlers = @{
    "set_profile"      = ${function:Invoke-SetProfile}
    "toggle_telemetry" = ${function:Invoke-ToggleTelemetry}
    "restart_services" = ${function:Invoke-RestartServices}
    "get_status"       = ${function:Invoke-GetStatus}
    "update_sysmon"    = ${function:Invoke-UpdateSysmon}
}

# ── Send result back to server ─────────────────────────────────────────────

function Send-Result {
    param([string]$CommandId, [hashtable]$Result)
    $resultObj = [ordered]@{
        command_id  = $CommandId
        agent_id    = $AgentId
        status      = $Result.status
        output      = "$($Result.output)"
        executed_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    $payload = ConvertTo-Json $resultObj -Compress -Depth 10
    $sig     = Get-HmacHex -Key $secretBytes -Message $payload
    $body    = @{ signed_payload = $payload; signature = $sig } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod -Method Post `
            -Uri "$ServerUrl/agents/$AgentId/results" `
            -Headers @{ "Authorization" = (Get-AuthHeader); "Content-Type" = "application/json" } `
            -Body $body -TimeoutSec 30 -UseBasicParsing | Out-Null
    } catch {
        Write-Log "ERROR" "Failed to post result for ${CommandId}: $_"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
#                              MAIN POLL LOOP
# ═══════════════════════════════════════════════════════════════════════════

try {
    Write-Log "INFO" "Polling $ServerUrl/agents/$AgentId/poll"

    $resp = Invoke-RestMethod -Method Post `
        -Uri "$ServerUrl/agents/$AgentId/poll" `
        -Headers @{ "Authorization" = (Get-AuthHeader); "Content-Type" = "application/json" } `
        -Body "{}" -TimeoutSec 30 -UseBasicParsing

    if (-not $resp.commands -or $resp.commands.Count -eq 0) {
        Write-Log "INFO" "No pending commands"
        exit 0
    }

    foreach ($env in $resp.commands) {
        # 1. Verify signature over the inner payload bytes
        $expectedSig = Get-HmacHex -Key $secretBytes -Message $env.signed_payload
        if ($expectedSig -ne $env.signature) {
            Write-Log "SECURITY" "Signature mismatch — DROPPING command (possible tamper)"
            continue
        }

        # 2. Parse the inner command JSON
        try {
            $cmd = ConvertFrom-Json $env.signed_payload
        } catch {
            Write-Log "ERROR" "Could not parse command payload: $_"
            continue
        }

        # 3. Verify it's targeted at us
        if ($cmd.agent_id -ne $AgentId) {
            Write-Log "SECURITY" "Command targeted $($cmd.agent_id) but we are $AgentId — DROPPING"
            continue
        }

        # 4. Verify expiry
        try {
            $expUtc = [DateTime]::Parse($cmd.expires_at).ToUniversalTime()
            if ($expUtc -lt [DateTime]::UtcNow) {
                Write-Log "WARN" "Command $($cmd.command_id) ($($cmd.command_type)) expired — skipping"
                Send-Result $cmd.command_id @{ status = "rejected"; output = "Command expired before execution" }
                continue
            }
        } catch {
            Write-Log "ERROR" "Bad expires_at on $($cmd.command_id): $_"
            continue
        }

        Write-Log "INFO" "Executing $($cmd.command_type) [$($cmd.command_id)]"

        # 5. Dispatch via whitelist
        $handler = $Handlers["$($cmd.command_type)"]
        if (-not $handler) {
            $result = @{ status = "rejected"; output = "Unknown command type: $($cmd.command_type)" }
        } else {
            try {
                $params = if ($cmd.params) { $cmd.params } else { @{} }
                $result = & $handler $params
            } catch {
                $result = @{ status = "failure"; output = "Handler exception: $_" }
            }
        }

        Write-Log "INFO" ("Result: {0} - {1}" -f $result.status,
            "$($result.output)".Substring(0, [Math]::Min(160, "$($result.output)".Length)))

        # 6. Report back
        Send-Result $cmd.command_id $result
    }
} catch {
    Write-Log "ERROR" "Poll iteration failed: $_"
    exit 1
}
