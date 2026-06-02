# scripts/agent_command_handler.ps1
# ===========================================================================
#   APT Threat Hunting Platform - Agent Command Handler
#
#   Runs as SYSTEM via Task Scheduler every 60 seconds. Polls the AI Platform
#   for pending commands, verifies HMAC signatures, executes WHITELISTED
#   operations, and reports results back.
#
#   Configuration (registry HKLM:\SOFTWARE\APTPlatform):
#     AgentId               - this host's identifier (e.g. computer name)
#     ServerUrl             - base URL of AI Platform API (e.g. https://api:8000)
#     AgentSecret           - base64 of DPAPI-encrypted HMAC secret (machine scope)
#     ServerIP              - Wazuh manager IP (used by SET_PROFILE re-deploy)
#     RegistrationPassword  - used by SET_PROFILE re-deploy
#     Profile               - current profile (Lean|Balanced|Full)
#     ScriptDir             - directory containing deploy_endpoint.ps1
#
#   SECURITY MODEL
#   * Agent secret: never leaves DPAPI-encrypted form on disk.
#   * Every command from server is HMAC-SHA256 signed; we verify before exec.
#   * Replay defense: server includes monotonic sequence + expires_at; we
#     drop expired commands and the server itself drops out-of-window auth.
#   * Whitelist: only command types in $Handlers will execute. Anything else
#     is rejected and reported back as "rejected".
#
#   PANIC-LOCAL RECOVERY
#   Invocation with -PanicUnisolate tears down isolation entirely from the
#   local host, without any server round-trip -- used by:
#     - the deadman scheduled task when the TTL expires;
#     - an admin physically at the host when the platform is unreachable.
#   The teardown writes a panic marker into the registry; the next normal
#   poll iteration back-reports the panic in its heartbeat so the platform
#   audit trail captures the off-network event.
# ===========================================================================

param(
    [switch]$PanicUnisolate,
    [string]$Reason = "operator-manual",
    # -SelfTest is invoked by _HandlerFetchAndApply's post-write verification
    # to prove the freshly-written script can be loaded by powershell.exe AND
    # bind switch arguments correctly. Returns "SELFTEST_OK" on stdout and
    # exits 0 BEFORE touching the registry, decrypting the secret, or doing
    # any I/O -- the test isolates "can this file be invoked", nothing more.
    # Critical for catching encoding/BOM corruption that mutates between the
    # in-memory string we hashed and the bytes that land on disk.
    [switch]$SelfTest
)

# -- Self-test fast-path. MUST run before any other code so registry / DPAPI
#    failures don't mask the actual self-test result. Output goes to stdout
#    so the OTA post-write check can grep for SELFTEST_OK regardless of
#    handler.log state. ---------------------------------------------------
if ($SelfTest) {
    Write-Output "SELFTEST_OK"
    exit 0
}

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

# -- Load configuration -----------------------------------------------------

try {
    $AgentId   = Get-Setting "AgentId"
    $ServerUrl = (Get-Setting "ServerUrl").TrimEnd("/")
    $SecretEnc = Get-Setting "AgentSecret"
    $ScriptDir = Get-Setting "ScriptDir" $PSScriptRoot
} catch {
    Write-Log "FATAL" "$_"
    exit 1
}

# -- Decrypt agent secret via DPAPI (machine scope) -------------------------

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

# -- Crypto helpers ---------------------------------------------------------

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
    # PS 5.1 bug: Get-Date -UFormat %s returns LOCAL time treated as UTC.
    # On a non-UTC host this signs a timestamp offset by the local TZ, and
    # the server rejects it as "Timestamp out of range".
    # Use UtcNow + epoch math instead.
    #
    # NOTE: this only signs whatever the OS believes UTC currently is. If the
    # Windows system clock itself is wrong, the signed ts will be wrong and
    # the server WILL 401. The self-heal helpers immediately below
    # (_TimeSyncForce / _TimeSyncIfStale) handle that case. See the LOUD
    # comment block in scripts/deploy_endpoint.ps1 Step 6 for the full story.
    $ts      = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $payload = "{0}:{1}" -f $AgentId, $ts
    $sig     = Get-HmacHex -Key $secretBytes -Message $payload
    return "APT-HMAC agent_id=$AgentId,ts=$ts,sig=$sig"
}

# ===========================================================================
#  CLOCK-SKEW SELF-HEAL  --  see LOUD comment in deploy_endpoint.ps1 Step 6
# ===========================================================================
#  HMAC auth bricks if the endpoint's clock drifts >5min from the server.
#  Two-layer protection:
#    _TimeSyncIfStale  -> called at top of each poll; resyncs once an hour
#                        so slow drift never breaches the HMAC window
#    _TimeSyncForce    -> called reactively when a request 401s; debounced
#                        to 120s so a permanently-no-NTP LAN doesn't spam
#
#  DO NOT remove. DO NOT widen the 5-min HMAC window in shared/commands.py
#  as a "fix" -- the right answer is to keep clocks in sync.
# ===========================================================================

function _TimeSyncForce {
    param([string]$Reason = "manual")

    # Debounce: skip if we attempted within the last 120s. Without this, an
    # endpoint with no reachable NTP source would call w32tm every poll and
    # spam handler.log forever.
    try {
        $lastAtt = (Get-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" `
                    -Name "LastTimeSyncAttemptAt" -ErrorAction SilentlyContinue).LastTimeSyncAttemptAt
        $now = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        if ($lastAtt) {
            $sinceAttempt = $now - [int64]$lastAtt
            if ($sinceAttempt -lt 120) {
                Write-Log "INFO" "TimeSync ($Reason): skipped (last attempt ${sinceAttempt}s ago)"
                return $false
            }
        }
    } catch {}

    Set-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" -Name "LastTimeSyncAttemptAt" `
        -Value ([int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())) -ErrorAction SilentlyContinue

    try {
        # Relax phase-correction so a large jump is allowed. Without this,
        # Windows refuses to step skews >15min and the endpoint stays stuck.
        $cfg = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
        if (Test-Path $cfg) {
            Set-ItemProperty -Path $cfg -Name "MaxPosPhaseCorrection" `
                -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $cfg -Name "MaxNegPhaseCorrection" `
                -Value 0xFFFFFFFF -Type DWord -ErrorAction SilentlyContinue
        }

        # Ensure w32time is running.
        $svc = Get-Service -Name w32time -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Start-Service -Name w32time -ErrorAction SilentlyContinue
        }

        # Configure peers: public NTP first, platform-server IP as LAN fallback.
        $serverIp = (Get-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" `
                     -Name "ServerIP" -ErrorAction SilentlyContinue).ServerIP
        $peers = "time.windows.com,0x9 pool.ntp.org,0x9"
        if ($serverIp) { $peers = "$peers $serverIp,0x9" }
        & w32tm /config /manualpeerlist:"$peers" /syncfromflags:manual `
                /reliable:no /update 2>&1 | Out-Null

        # NOTE: w32tm /resync does NOT accept a /force flag (it's a made-up
        # parameter -- the "force a large jump" behaviour comes from the
        # MaxPos/NegPhaseCorrection registry writes above, NOT from a CLI flag).
        # Valid switches: /computer /nowait /rediscover /soft.
        $out = & w32tm /resync /rediscover 2>&1
        $joined = ($out -join '; ').Trim()
        Write-Log "INFO" "TimeSync ($Reason): $joined"

        # NOTE: explicit if/else (PS 5.1 try-block parser hardening).
        $ok = $false
        if ($joined -match "successfully") { $ok = $true }
        elseif ($joined -notmatch "(?i)(error|fail)") { $ok = $true }

        if ($ok) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" -Name "LastTimeSyncOkAt" `
                -Value ([int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())) -ErrorAction SilentlyContinue
        }
        return $ok
    } catch {
        Write-Log "WARN" "TimeSync ($Reason) exception: $_"
        return $false
    }
}

function _TimeSyncIfStale {
    # Periodic hourly resync so slow drift heals before crossing the
    # 5-min HMAC window. Cheap on a working NTP path (~50ms).
    try {
        $lastOk = (Get-ItemProperty -Path "HKLM:\SOFTWARE\APTPlatform" `
                   -Name "LastTimeSyncOkAt" -ErrorAction SilentlyContinue).LastTimeSyncOkAt
        $now = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        # NOTE: explicit if/else (PS 5.1 try-block parser hardening).
        $needsSync = $false
        if (-not $lastOk) {
            $needsSync = $true
        } else {
            $age = $now - [int64]$lastOk
            if ($age -ge 3600) { $needsSync = $true }
        }
        if ($needsSync) {
            $null = _TimeSyncForce -Reason "periodic"
        }
    } catch {
        # Silent -- periodic sync failure is non-fatal; reactive on-401 will catch up.
    }
}

# -- Whitelisted command handlers -------------------------------------------
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
        # Pass PlatformApiUrl so deploy_endpoint.ps1 defaults the Wazuh MSI +
        # Sysmon ZIP download URLs to the platform server cache. Without it,
        # any re-download would fall back to packages.wazuh.com /
        # download.sysinternals.com -- broken on air-gapped networks (and
        # against the Tanzania data-residency policy).
        $platform = Get-Setting "ServerUrl" $null
        $deployArgs = @{
            ServerIP             = $serverIP
            RegistrationPassword = $regPass
            Profile              = $profile
        }
        if ($platform) { $deployArgs.PlatformApiUrl = $platform }
        $output = & $deploy @deployArgs 2>&1 | Out-String
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
                # NOTE: explicit if/else (not `$x = if (..) {..} else {..}`)
                # inside try blocks -- PS 5.1's parser intermittently
                # mis-nests with the latter, as documented at the top of
                # _IsolationTeardown.
                $state = "disable"
                if ($enabled) { $state = "enable" }
                netsh advfirewall set allprofiles logging droppedconnections $state | Out-Null
            }
            "fim" {
                # FIM is owned by Wazuh agent. Toggle the <syscheck><disabled> via
                # a scheduled deploy_endpoint.ps1 re-run? For now: not supported
                # without a profile change.
                return @{ status = "rejected"; output = "FIM toggle requires a profile change (use set_profile)" }
            }
        }
        $verb = "disabled"
        if ($enabled) { $verb = "enabled" }
        return @{ status = "success"; output = "$source $verb" }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

function Invoke-RestartServices {
    param($Params)
    $svc = "$($Params.service)"

    # Sysmon hardens its service DACL against SCM stop/start as an anti-tamper
    # measure. The supported way to apply a new Sysmon config is `Sysmon64.exe
    # -c <config.xml>` (live reload, no service restart) - which is what the
    # update_sysmon handler does. So "sysmon" maps to a no-op here, and "all"
    # only actually restarts Wazuh.
    $results = @()
    $hadFailure = $false

    function Try-Restart {
        param([string]$Name)
        try {
            Restart-Service -Name $Name -Force -ErrorAction Stop
            return @{ ok = $true; msg = "$Name restarted" }
        } catch {
            return @{ ok = $false; msg = "$Name failed: $_" }
        }
    }

    switch ($svc) {
        "wazuh"  {
            $r = Try-Restart "WazuhSvc"
            $results += $r.msg
            if (-not $r.ok) { $hadFailure = $true }
        }
        "sysmon" {
            $results += "Sysmon cannot be restarted via SCM (hardened DACL). Use update_sysmon to push a new config."
            $hadFailure = $true
        }
        "all"    {
            $r = Try-Restart "WazuhSvc"
            $results += $r.msg
            if (-not $r.ok) { $hadFailure = $true }
            $results += "Sysmon left running (anti-tamper DACL; use update_sysmon to apply config changes)."
        }
        default {
            return @{ status = "rejected"; output = "Invalid service: $svc" }
        }
    }

    $output = $results -join "; "
    $status = if ($hadFailure) { "failure" } else { "success" }
    return @{ status = $status; output = $output }
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
        # Basic sanity check - must contain <Sysmon> root
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

# ===========================================================================
#                              HOST ISOLATION
# ===========================================================================
# Three levels (light / standard / full) -- all fully reversible via three
# independent paths: remote UNISOLATE command, local deadman scheduled task,
# and a -PanicUnisolate switch run by an admin on-host.
#
# Every artefact (firewall rules, profile defaults, disabled adapters,
# scheduled task) is tagged or recorded in the registry so unisolate is
# atomic and deterministic -- no orphaned rules, no half-enabled adapters.
#
# Phase 2 of the rollout ships the STANDARD level handler + helpers. Light
# and Full return "rejected" with a clear message until Phase 3 / 4 land.
# ===========================================================================

$IsolationLogFile = Join-Path $LogDir "isolation.log"

function _IsolationLog {
    param([string]$Level, [string]$Msg)
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "$ts [$Level] $Msg" | Out-File -FilePath $IsolationLogFile -Append -Encoding utf8
}

# Parse the ServerUrl into host + port. The port defaults to 443/80 by scheme
# when the URL omits it (some installs hit https://api without a port).
function _IsolationParseUrl {
    param([string]$Url)
    $u = [Uri]$Url
    $port = $u.Port
    if ($port -lt 0 -or $port -eq 0) {
        $port = if ($u.Scheme -eq "https") { 443 } else { 80 }
    }
    return @{ Host = $u.Host; Port = $port }
}

# Resolve a hostname to an IPv4 literal. If already a literal, returns as-is.
# Lifeline rules MUST use IP literals -- the agent's local DNS can be
# severed by the level-specific block rules.
function _IsolationResolveIp {
    param([string]$HostOrIp)
    if ($HostOrIp -match "^\d+\.\d+\.\d+\.\d+$") { return $HostOrIp }
    $entries = [System.Net.Dns]::GetHostAddresses($HostOrIp)
    $v4 = $entries | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1
    if (-not $v4) { throw "no IPv4 address for $HostOrIp" }
    return $v4.IPAddressToString
}

# Read ServerUrl + ServerIP from registry, resolve to IPs + ports.
function _IsolationResolveLifeline {
    $apiUrl  = Get-Setting "ServerUrl"
    $wazuhIp = Get-Setting "ServerIP"
    $parsed  = _IsolationParseUrl $apiUrl
    $apiIp   = _IsolationResolveIp $parsed.Host
    if (-not ($wazuhIp -match "^\d+\.\d+\.\d+\.\d+$")) {
        throw "ServerIP registry value is not a literal IPv4: $wazuhIp"
    }
    return @{
        ApiHost     = $parsed.Host
        ApiIp       = $apiIp
        ApiPort     = $parsed.Port
        WazuhIp     = $wazuhIp
        WazuhAgent  = 1514
        WazuhEnroll = 1515
    }
}

# +==========================================================================+
# |  LIFELINE RULES  --  LOAD-BEARING. DO NOT REMOVE / TIGHTEN WITHOUT       |
# |                     READING THE NOTES BELOW.                             |
# +==========================================================================+
# |  The lifeline is the set of outbound Allow rules that survive the        |
# |  default-Block we set in _IsolationApplyStandard / _IsolationApplyFull.  |
# |  Every rule here is NECESSARY for the isolation to remain SAFELY         |
# |  RECOVERABLE -- strip any of them and the next incident becomes a        |
# |  forensic visit instead of a click.                                      |
# |                                                                          |
# |  Required by category:                                                   |
# |    1. Platform reach    -- TCP to API + Wazuh agent + Wazuh enroll.      |
# |                            Without these, the agent can never poll for   |
# |                            UNISOLATE and is stranded until the deadman   |
# |                            fires (up to 24h).                            |
# |    2. DHCP              -- UDP 67/68 broadcast. Without it, Wi-Fi DHCP   |
# |                            lease renewal fails -> endpoint goes offline  |
# |                            after ~50% of original lease (~30 min on a    |
# |                            typical 1h lease) -> kills the lifeline.      |
# |    3. NTP               -- UDP 123 outbound. Without it, w32tm can't     |
# |                            sync, the clock drifts past the 5-min HMAC    |
# |                            window, EVERY signed request 401s, agent      |
# |                            is stranded. (2026-06-01 incident: DESKTOP-   |
# |                            BQKEGGO sat at 401s for hours during a Full   |
# |                            isolate because NTP was collateral-blocked.)  |
# |    4. DNS to known servers -- UDP 53 to the DNS servers the OS already   |
# |                            had configured at apply-time. Lets w32tm      |
# |                            resolve time.windows.com / pool.ntp.org;      |
# |                            without it the catch-all NTP rule is unused   |
# |                            because w32tm has no IP to send to.           |
# |                                                                          |
# |  WHY THIS IS NOT A "WEAKENING" OF ISOLATION:                             |
# |    UDP 123 and UDP 53 are one-way / broadcast-style protocols. They      |
# |    are NOT viable interactive C2 channels. Modern attackers use HTTP/S   |
# |    (TCP 443) or specialised TCP -- both still blocked by the default-    |
# |    Block. The cost of dropping NTP/DNS is "endpoint can't recover        |
# |    without on-host admin"; the benefit is "marginally tighter UDP        |
# |    surface" -- not worth the trade.                                      |
# |                                                                          |
# |  IF you must tighten:                                                    |
# |    1. Run an in-stack NTP daemon on the platform server                  |
# |    2. Replace UDP 123 catch-all with UDP 123 -> <platform-server-IP>     |
# |    3. Replace UDP 53 catch-all with UDP 53 -> <platform-server-IP>       |
# |    4. KEEP the LOUD comment so the next dev doesn't strip those.         |
# |                                                                          |
# |  NOTE on rule precedence -- DO NOT add `-OverrideBlockRules $true`:      |
# |    Inbound-only AND requires IPsec auth. Used on plain outbound Allow,   |
# |    Windows promotes it to `-Action Bypass` and rejects with "Allow-      |
# |    Bypass action specified, but the rule does not meet allow-bypass      |
# |    criteria". It is also UNNECESSARY -- explicit Allow for a specific    |
# |    tuple naturally takes precedence over a profile default-Block.        |
# |    (2026-05-31 incident: Full isolate rolled back at apply-time          |
# |    because the lifeline rules couldn't be created.)                      |
# +==========================================================================+
function _IsolationApplyLifeline {
    param($Lifeline)
    $rules = @()

    # -- 1. Platform reach: TCP to API + Wazuh ports -------------------------
    $created = @(
        @{ Name = "APT-ISOLATE-LIFELINE-API";     Ip = $Lifeline.ApiIp;   Port = $Lifeline.ApiPort     },
        @{ Name = "APT-ISOLATE-LIFELINE-WAZUH-A"; Ip = $Lifeline.WazuhIp; Port = $Lifeline.WazuhAgent  },
        @{ Name = "APT-ISOLATE-LIFELINE-WAZUH-E"; Ip = $Lifeline.WazuhIp; Port = $Lifeline.WazuhEnroll }
    )
    foreach ($r in $created) {
        New-NetFirewallRule -DisplayName $r.Name `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemoteAddress $r.Ip -RemotePort $r.Port `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation lifeline (platform reach)" `
            -ErrorAction Stop | Out-Null
        $rules += $r.Name
    }

    # -- 2. DHCP: UDP 67/68 for Wi-Fi lease renewal --------------------------
    New-NetFirewallRule -DisplayName "APT-ISOLATE-LIFELINE-DHCP" `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 67,68 `
        -Profile Any -Enabled True `
        -Description "APT Platform isolation lifeline (DHCP renewal)" `
        -ErrorAction Stop | Out-Null
    $rules += "APT-ISOLATE-LIFELINE-DHCP"

    # -- 3. NTP: UDP 123 catch-all so w32tm can sync -------------------------
    # See LOUD comment above. Without this rule, prolonged isolation
    # guarantees the agent loses authentication and can only be recovered
    # via deadman timeout or on-host panic-local. Catch-all (any IP) so
    # whatever NTP source the OS picks works.
    New-NetFirewallRule -DisplayName "APT-ISOLATE-LIFELINE-NTP" `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 123 `
        -Profile Any -Enabled True `
        -Description "APT Platform isolation lifeline (NTP - clock sync must survive isolation)" `
        -ErrorAction Stop | Out-Null
    $rules += "APT-ISOLATE-LIFELINE-NTP"

    # -- 4. DNS to known servers ---------------------------------------------
    # Allow UDP 53 to whatever DNS servers the OS has configured AT APPLY
    # TIME (Get-DnsClientServerAddress). This lets w32tm resolve
    # time.windows.com / pool.ntp.org so NTP (rule 3 above) can actually
    # reach a peer. Snapshot is fine -- if the user roams to a new network
    # post-isolation, DHCP renewal (rule 2) handles a new lease but the
    # baked-in DNS rules become stale until unisolate. Acceptable.
    $dnsServers = @()
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.ServerAddresses } |
                      ForEach-Object { $_.ServerAddresses } |
                      Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -ne "127.0.0.1" } |
                      Sort-Object -Unique
    } catch { $dnsServers = @() }
    if ($dnsServers.Count -gt 0) {
        foreach ($dns in $dnsServers) {
            $dnsName = "APT-ISOLATE-LIFELINE-DNS-" + $dns.Replace(".", "_")
            New-NetFirewallRule -DisplayName $dnsName `
                -Direction Outbound -Action Allow `
                -Protocol UDP -RemoteAddress $dns -RemotePort 53 `
                -Profile Any -Enabled True `
                -Description "APT Platform isolation lifeline (DNS - w32tm peer resolution)" `
                -ErrorAction Stop | Out-Null
            $rules += $dnsName
        }
    } else {
        # No DNS servers discoverable -- fall back to a UDP 53 catch-all so
        # NTP peer resolution still works. Slightly looser but still safe
        # (DNS is one-way query/response, not a viable C2 channel).
        _IsolationLog "WARN" "no DNS servers discovered; adding UDP 53 catch-all lifeline"
        New-NetFirewallRule -DisplayName "APT-ISOLATE-LIFELINE-DNS-ANY" `
            -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation lifeline (DNS catch-all)" `
            -ErrorAction Stop | Out-Null
        $rules += "APT-ISOLATE-LIFELINE-DNS-ANY"
    }

    return $rules
}

# Save the current profile defaults (inbound + outbound) to registry so the
# unisolate path can restore them exactly. Idempotent -- second call is a no-op.
function _IsolationSaveProfileDefaults {
    $orig = @{}
    foreach ($p in @("Domain","Private","Public")) {
        $prof = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
        $orig[$p] = @{
            outbound = "$($prof.DefaultOutboundAction)"
            inbound  = "$($prof.DefaultInboundAction)"
        }
    }
    Set-ItemProperty -Path $RegPath -Name "IsolationOrigProfileDefaults" `
        -Value (ConvertTo-Json $orig -Compress)
}

# Inbound management-port blocks. Shared by Standard + Full.
# SMB / NetBIOS / RDP / WinRM. Blocks pivots INTO the host without breaking
# the lifeline (which is outbound from the agent).
function _IsolationApplyInboundManagementBlocks {
    param([string]$LevelTag)
    $rules = @()
    $ports = @(445, 139, 3389, 5985, 5986)
    foreach ($p in $ports) {
        $name = "APT-ISOLATE-$LevelTag-IN-TCP-$p"
        New-NetFirewallRule -DisplayName $name `
            -Direction Inbound -Action Block `
            -Protocol TCP -LocalPort $p `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation inbound mgmt block" `
            -ErrorAction Stop | Out-Null
        $rules += $name
    }
    return $rules
}

# Light level: keep general internet, block known lateral-movement +
# credential-pivot ports, restrict DNS to corporate resolvers.
function _IsolationApplyLight {
    param($Lifeline)
    $rules = @()

    # Outbound port blocks -- lateral movement + credential pivot.
    $outPorts = @(
        @{ Proto = "TCP"; Port = 445  },  # SMB
        @{ Proto = "TCP"; Port = 139  },  # NetBIOS session
        @{ Proto = "TCP"; Port = 3389 },  # RDP
        @{ Proto = "TCP"; Port = 5985 },  # WinRM HTTP
        @{ Proto = "TCP"; Port = 5986 },  # WinRM HTTPS
        @{ Proto = "TCP"; Port = 88   },  # Kerberos
        @{ Proto = "UDP"; Port = 88   },
        @{ Proto = "TCP"; Port = 464  },  # kpasswd
        @{ Proto = "UDP"; Port = 464  },
        @{ Proto = "UDP"; Port = 137  },  # NetBIOS name
        @{ Proto = "UDP"; Port = 138  },  # NetBIOS datagram
        @{ Proto = "UDP"; Port = 5353 }   # mDNS
    )
    foreach ($r in $outPorts) {
        $name = "APT-ISOLATE-LIGHT-OUT-{0}-{1}" -f $r.Proto, $r.Port
        New-NetFirewallRule -DisplayName $name `
            -Direction Outbound -Action Block `
            -Protocol $r.Proto -RemotePort $r.Port `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation lateral-movement block" `
            -ErrorAction Stop | Out-Null
        $rules += $name
    }

    # DNS containment: allow corporate DNS only.
    $corpDns = @()
    try {
        $corpDns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.ServerAddresses } |
                   ForEach-Object { $_.ServerAddresses } |
                   Where-Object { $_ -and $_ -ne "0.0.0.0" -and $_ -ne "127.0.0.1" } |
                   Sort-Object -Unique
    } catch { $corpDns = @() }

    if ($corpDns.Count -gt 0) {
        foreach ($dns in $corpDns) {
            $name = "APT-ISOLATE-LIGHT-DNS-ALLOW-" + $dns.Replace(".","_")
            # NOTE: NO -OverrideBlockRules. See comment on _IsolationApplyLifeline.
            New-NetFirewallRule -DisplayName $name `
                -Direction Outbound -Action Allow `
                -Protocol UDP -RemoteAddress $dns -RemotePort 53 `
                -Profile Any -Enabled True `
                -Description "APT Platform isolation corp DNS allow" `
                -ErrorAction Stop | Out-Null
            $rules += $name
        }
        # Block UDP 53 to everywhere else; the corp-DNS allow rules override
        # this block for their narrow scope.
        New-NetFirewallRule -DisplayName "APT-ISOLATE-LIGHT-DNS-BLOCK" `
            -Direction Outbound -Action Block `
            -Protocol UDP -RemotePort 53 `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation non-corp DNS block" `
            -ErrorAction Stop | Out-Null
        $rules += "APT-ISOLATE-LIGHT-DNS-BLOCK"
    } else {
        # No corp DNS discoverable -- leave DNS alone rather than blackhole it
        # and break browsing entirely. Log so the operator knows.
        _IsolationLog "WARN" "Light level: no corporate DNS detected; DNS containment skipped"
    }

    # Inbound mgmt blocks (5 rules).
    $rules += _IsolationApplyInboundManagementBlocks "LIGHT"
    return $rules
}

# Enable Windows Firewall in every profile + restore default rule precedence.
# CRITICAL: Set-NetFirewallProfile -DefaultOutboundAction Block is a NO-OP if
# the firewall itself is DISABLED for that profile (extremely common on Win 11
# Home + fresh installs, where Public is on but Private/Domain may be off).
# We must enable the firewall BEFORE setting the default, or the "block public
# internet" guarantee silently fails. (2026-05-31 incident: Full isolate
# reported success but 1.1.1.1:443 was still reachable -- root cause: active
# profile had `Enabled = False`.)
function _IsolationEnsureFirewallEnabled {
    foreach ($p in @("Domain","Private","Public")) {
        try {
            $prof = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
            if (-not $prof.Enabled) {
                Set-NetFirewallProfile -Profile $p -Enabled True -ErrorAction Stop
                _IsolationLog "INFO" "enabled firewall on profile '$p' (was disabled)"
            }
        } catch {
            _IsolationLog "WARN" "could not enable firewall profile '$p': $_"
        }
    }
}

# Log every profile's effective state -- diagnostic so failures like "block
# not effective" can be traced back to which profile was active + its rules.
function _IsolationLogProfileState {
    param([string]$Tag)
    try {
        foreach ($p in @("Domain","Private","Public")) {
            $prof = Get-NetFirewallProfile -Profile $p -ErrorAction SilentlyContinue
            if ($prof) {
                _IsolationLog "INFO" ("[{0}] profile={1} enabled={2} defaultOut={3} defaultIn={4}" -f `
                    $Tag, $p, $prof.Enabled, $prof.DefaultOutboundAction, $prof.DefaultInboundAction)
            }
        }
        # Also log which profile(s) are CURRENTLY active for the network connection.
        $conn = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        foreach ($c in $conn) {
            _IsolationLog "INFO" ("[{0}] active-conn iface={1} profile={2}" -f $Tag, $c.InterfaceAlias, $c.NetworkCategory)
        }
    } catch {
        _IsolationLog "WARN" "log profile state failed: $_"
    }
}

# Standard level: allow RFC1918 LAN, set profile default outbound to Block,
# block inbound management ports.
function _IsolationApplyStandard {
    param($Lifeline)
    $rules = @()
    foreach ($cidr in @("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) {
        $name = "APT-ISOLATE-STANDARD-ALLOW-LAN-" + $cidr.Replace("/","-").Replace(".","_")
        # NOTE: NO -OverrideBlockRules. See comment on _IsolationApplyLifeline.
        New-NetFirewallRule -DisplayName $name `
            -Direction Outbound -Action Allow `
            -RemoteAddress $cidr `
            -Profile Any -Enabled True `
            -Description "APT Platform isolation LAN allow" `
            -ErrorAction Stop | Out-Null
        $rules += $name
    }
    _IsolationSaveProfileDefaults
    _IsolationEnsureFirewallEnabled
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultOutboundAction Block -ErrorAction Stop
    _IsolationLogProfileState "STANDARD-after-apply"
    $rules += _IsolationApplyInboundManagementBlocks "STANDARD"
    return $rules
}

# Full level: lifeline only outbound, inbound also default-block, plus the
# management-port belt-and-braces. Adapter disable is layered on top by
# Invoke-Isolate after this helper succeeds.
function _IsolationApplyFull {
    param($Lifeline)
    $rules = @()
    _IsolationSaveProfileDefaults
    _IsolationEnsureFirewallEnabled
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultOutboundAction Block `
        -DefaultInboundAction  Block `
        -ErrorAction Stop
    _IsolationLogProfileState "FULL-after-apply"
    $rules += _IsolationApplyInboundManagementBlocks "FULL"
    return $rules
}

# Default adapter-pattern filter -- matched against InterfaceDescription. The
# operator can override at deploy time via a registry value
# `IsolationAdapterFilter` (REG_SZ regex) without modifying the script.
$DefaultVpnAdapterPattern = '(?i)(TAP|TUN|WireGuard|OpenVPN|Cisco AnyConnect|GlobalProtect|FortiClient|Hyper-V|vEthernet|VMware|VirtualBox|VPN)'

# Identify candidate virtual / VPN adapters. Only considers currently-up
# adapters so we never disable something that was already off (would dirty
# the restore set on unisolate).
function _IsolationFindVpnAdapters {
    $pattern = $DefaultVpnAdapterPattern
    try {
        $override = (Get-ItemProperty -Path $RegPath -Name "IsolationAdapterFilter" -ErrorAction SilentlyContinue).IsolationAdapterFilter
        if (-not [string]::IsNullOrWhiteSpace($override)) { $pattern = $override }
    } catch { }

    return Get-NetAdapter -ErrorAction SilentlyContinue |
           Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -match $pattern } |
           Select-Object Name, InterfaceDescription
}

# Disable adapters discovered by _IsolationFindVpnAdapters. The exact names
# of those we disabled are written to IsolationDisabledAdapters (REG_MULTI_SZ)
# BEFORE the disable runs -- so even if PowerShell is killed mid-loop, the
# restore path knows what to re-enable.
function _IsolationDisableAdapters {
    $cands = @(_IsolationFindVpnAdapters)
    if ($cands.Count -eq 0) {
        # Still record the empty list so reading the value later is
        # deterministic.
        New-ItemProperty -Path $RegPath -Name "IsolationDisabledAdapters" `
            -Value @() -PropertyType MultiString -Force | Out-Null
        return @()
    }
    $names = @($cands | ForEach-Object { $_.Name })
    # Persist BEFORE acting -- crash-safety.
    New-ItemProperty -Path $RegPath -Name "IsolationDisabledAdapters" `
        -Value $names -PropertyType MultiString -Force | Out-Null
    foreach ($a in $cands) {
        try {
            Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
            _IsolationLog "INFO" "adapter-disable name='$($a.Name)' desc='$($a.InterfaceDescription)'"
        } catch {
            _IsolationLog "WARN" "adapter-disable failed name='$($a.Name)': $_"
        }
    }
    return $names
}

# Find a logged-on interactive user as "DOMAIN\username" (or just "username"
# when no domain is present), or $null if none. Returns the user that owns
# the currently-running explorer.exe -- that's by definition the interactive
# session user.
#
# Tried in order:
#   1. CIM Win32_Process explorer.exe owner   -- works on Home / Pro / Enterprise / Server
#   2. quser                                  -- Pro/Enterprise only (Home omits it)
#   3. LastLoggedOnUser registry              -- last-resort, may be stale post-logout
#
# The format returned MUST be acceptable to New-ScheduledTaskPrincipal -UserId
# (SAM `DOMAIN\user`, UPN `user@domain`, or bare `user`). MicrosoftAccount\...
# values from the LogonUI registry can be problematic; CIM gives us the
# canonical local/domain SAM form.
function _IsolationFindInteractiveUser {
    # Method 1: CIM -- the explorer.exe owner is the interactive user.
    try {
        $procs = Get-CimInstance -ClassName Win32_Process `
                    -Filter "Name='explorer.exe'" -ErrorAction Stop
        foreach ($p in $procs) {
            $own = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($own -and $own.User) {
                if ($own.Domain) { return ("{0}\{1}" -f $own.Domain, $own.User) }
                return $own.User
            }
        }
    } catch { }
    # Method 2: quser (Pro/Enterprise).
    try {
        $raw = quser 2>$null
        if ($raw) {
            $line = $raw | Where-Object { $_ -match "Active" } | Select-Object -First 1
            if ($line) {
                $parts = ($line -split "\s+") | Where-Object { $_ }
                $name = $parts[0].TrimStart(">")
                if ($name -and $name -ne "USERNAME") { return $name }
            }
        }
    } catch { }
    # Method 3: registry (may be stale).
    try {
        $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        $last = (Get-ItemProperty -Path $key -Name "LastLoggedOnUser" -ErrorAction SilentlyContinue).LastLoggedOnUser
        if ($last) { return $last.TrimStart("\") }
    } catch { }
    return $null
}

# Show a system message to the interactive user. SYSTEM can't post a toast
# directly into the user's session, so we register a one-shot scheduled task
# running as the user, fire it, then unregister. Works on Win 10 + Win 11
# Home / Pro / Enterprise (no msg.exe / no WinRT session dependency).
#
# `-Reason` is the operator's free-text justification captured by the
# dashboard / mobile picker. When present we append it to the body so the
# endpoint user knows WHY their device is suddenly constrained. Truncated
# to 200 chars and stripped of control characters before display.
function _IsolationToast {
    param(
        [string]$Title,
        [string]$Body,
        [string]$Reason = "",
        # MessageBoxImage names: Information / Warning / Stop / Error / Question.
        # Use Information for "received", Warning for "applied", Stop for "failed".
        [ValidateSet("Information","Warning","Stop","Error","Question","None")]
        [string]$Icon = "Warning"
    )
    try {
        $userName = _IsolationFindInteractiveUser
        if (-not $userName) {
            _IsolationLog "INFO" "toast skipped: no interactive user (title='$Title')"
            return
        }
        # Build the final body. Single-quoted PS literals don't interpret \n
        # so use a visible separator that still reads cleanly in a Windows
        # MessageBox.
        $fullBody = $Body
        if (-not [string]::IsNullOrWhiteSpace($Reason)) {
            $cleanReason = ($Reason -replace "[\r\n\t]+", " ").Trim()
            if ($cleanReason.Length -gt 200) {
                $cleanReason = $cleanReason.Substring(0, 197) + "..."
            }
            $fullBody = "$Body`n`nReason: $cleanReason"
        }
        # Unique per-call so back-to-back toasts (received -> applied / failed)
        # don't collide on the same task name. The pre-existing toast may still
        # be on screen waiting for the user to click OK; the new task fires its
        # own MessageBox in the user session independently.
        $stamp      = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $taskName   = "APTPlatformIsolationToast_$stamp"
        $scriptPath = Join-Path $LogDir ("toast_{0}.ps1" -f $stamp)
        $escTitle = $Title -replace "'", "''"
        $escBody  = $fullBody -replace "'", "''"
        @"
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show('$escBody', '$escTitle', 'OK', '$Icon') | Out-Null
"@ | Out-File -FilePath $scriptPath -Encoding utf8 -Force

        $action    = New-ScheduledTaskAction `
                        -Execute "powershell.exe" `
                        -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        # CRITICAL: -LogonType Interactive. The default LogonType is `Password`
        # which requires a stored credential -- Register-ScheduledTask from
        # SYSTEM without one fails silently (the task registers but never
        # runs, so the MessageBox never renders). `Interactive` runs the task
        # in the existing user logon session WITH desktop access, which is
        # exactly what we need to pop a MessageBox in front of the user.
        # (2026-05-31 incident: toasts silently no-op'd because of this.)
        $principal = New-ScheduledTaskPrincipal -UserId $userName `
                        -LogonType Interactive -RunLevel Limited
        # NOTE: do NOT add battery-related parameters here. On the Win 11
        # ScheduledTasks module, both -AllowStartIfOnBatteries and
        # -DisallowStartIfOnBatteries:$false trigger:
        #   "A parameter cannot be found that matches parameter name 'X'"
        # which causes the Register-ScheduledTask to throw and the toast (or
        # deadman -- see _IsolationRegisterDeadman) to silently no-op.
        # Defaults are: allow start on batteries, don't stop on batteries --
        # exactly what we want for both toasts and deadman. Don't "improve"
        # this by re-adding the params. (2026-06-01 incident: every toast +
        # the deadman safety net failed for two days because of this.)
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        Register-ScheduledTask -TaskName $taskName `
            -Action $action -Principal $principal -Settings $settings `
            -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        # Give the box a beat to render before we unregister. The MessageBox
        # itself stays on screen until the user clicks OK -- unregistering the
        # task definition does not stop the already-running process.
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        _IsolationLog "INFO" "toast queued for user '$userName' title='$Title' icon=$Icon"
    } catch {
        _IsolationLog "WARN" "toast failed: $_"
    }
}

# Tier-aware copy for the three isolation notification moments. Centralised
# here so the strings stay consistent across received / applied / failed and
# across light / standard / full. The Reason from the operator is appended by
# _IsolationToast itself (truncated to 200 chars, control chars stripped).
function _IsolationToastForLevel {
    param(
        [ValidateSet("received","applied","failed")] [string]$Moment,
        [ValidateSet("light","standard","full")]     [string]$Level,
        [string]$Reason = "",
        [string]$Detail = ""
    )
    $title = ""
    $body  = ""
    $icon  = "Warning"
    switch ($Moment) {
        "received" {
            $icon = "Information"
            $title = "Security action initiated"
            switch ($Level) {
                "light"    { $body = "A security review is being applied to this device. You can continue working -- you may notice some internal services becoming temporarily unreachable." }
                "standard" { $body = "An isolation procedure is being applied to this device. Public internet access will be blocked. Local network and IT systems will remain reachable." }
                "full"     { $body = "A full isolation procedure is being applied to this device. ALL network access will be blocked except for the security platform. Please contact IT." }
            }
        }
        "applied" {
            $icon = "Warning"
            switch ($Level) {
                "light" {
                    $title = "Security review active on this device"
                    $body  = "A security review is in progress. Lateral-movement paths and unauthorized DNS are blocked. You can continue working normally."
                }
                "standard" {
                    $title = "Device quarantined by security team"
                    $body  = "Public internet access is blocked. Local network and IT systems remain reachable. Please contact IT to restore full connectivity."
                }
                "full" {
                    $title = "Device isolated by security team"
                    $body  = "Network access has been restricted to the security platform only. VPN tunnels have been disabled. Please contact IT to restore connectivity."
                }
            }
        }
        "failed" {
            $icon = "Stop"
            $title = "Security action could not be applied"
            $base = "An isolation procedure could not be applied."
            if ($Level -eq "light")    { $base = "A security review could not be initiated." }
            if ($Level -eq "full")     { $base = "A full isolation procedure could not be applied." }
            $body = "$base Your device remains in its previous state. IT has been notified."
            if (-not [string]::IsNullOrWhiteSpace($Detail)) {
                $cleanDetail = ($Detail -replace "[\r\n\t]+", " ").Trim()
                if ($cleanDetail.Length -gt 160) {
                    $cleanDetail = $cleanDetail.Substring(0, 157) + "..."
                }
                $body = "$body`n`nDetail: $cleanDetail"
            }
        }
    }
    _IsolationToast -Title $title -Body $body -Reason $Reason -Icon $icon
}

$DeadmanTaskName = "APTPlatformIsolationDeadman"

# Register a one-shot scheduled task that runs as SYSTEM and invokes this
# script with -PanicUnisolate at the supplied deadline. Idempotent: any
# previous deadman is replaced.
function _IsolationRegisterDeadman {
    param([datetime]$DeadlineUtc)
    try {
        Unregister-ScheduledTask -TaskName $DeadmanTaskName -Confirm:$false -ErrorAction SilentlyContinue

        # The path to THIS script -- we re-invoke it with -PanicUnisolate.
        # Explicit if/else avoids the PS 5.1 try-block parser quirk.
        $thisScript = (Join-Path $ScriptDir "agent_command_handler.ps1")
        if ($PSCommandPath) { $thisScript = $PSCommandPath }

        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$thisScript`" -PanicUnisolate -Reason `"deadman:ttl-expired`""

        # One-shot trigger at the deadline (local time -- Task Scheduler
        # converts internally; we pass DeadlineUtc converted to local).
        $deadlineLocal = $DeadlineUtc.ToLocalTime()
        $trigger = New-ScheduledTaskTrigger -Once -At $deadlineLocal

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
        # NOTE: minimal SettingsSet. -StartWhenAvailable is critical (deadman
        # must fire when the laptop wakes up if it was off at the deadline).
        # Do NOT add battery-related parameters -- see comment in _IsolationToast.
        $settings  = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
            -StartWhenAvailable

        Register-ScheduledTask -TaskName $DeadmanTaskName `
            -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "APT Platform isolation deadman -- auto-unisolates if the SOC does not lift containment by the TTL." `
            -Force -ErrorAction Stop | Out-Null

        _IsolationLog "INFO" "deadman registered fire_at=$($deadlineLocal.ToString('s'))"
    } catch {
        _IsolationLog "ERROR" "deadman registration failed: $_"
        throw
    }
}

function _IsolationUnregisterDeadman {
    try {
        Unregister-ScheduledTask -TaskName $DeadmanTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        _IsolationLog "WARN" "deadman unregister failed: $_"
    }
}

# Self-heal -- if registry says we're isolated but the lifeline rule has gone
# missing (manual user removal, AV tamper, GPO clobber), re-apply the level.
# Called once per poll iteration so a defection has a max 60-s recovery time.
function _IsolationSelfHeal {
    $state = _IsolationReadState
    if (-not $state) { return }
    try {
        $present = Get-NetFirewallRule -DisplayName "APT-ISOLATE-LIFELINE-API" -ErrorAction SilentlyContinue
        if ($present) { return }   # rules intact, nothing to do
        _IsolationLog "WARN" "self-heal: lifeline rule missing while isolated; re-applying level=$($state.Level)"
        # Re-resolve lifeline (IP may have changed) and re-apply.
        $lifeline = _IsolationResolveLifeline
        # Wipe any stragglers then re-apply.
        _IsolationTeardown
        _IsolationApplyLifeline $lifeline | Out-Null
        switch ($state.Level) {
            "light"    { _IsolationApplyLight    $lifeline | Out-Null }
            "standard" { _IsolationApplyStandard $lifeline | Out-Null }
            "full"     {
                _IsolationApplyFull $lifeline | Out-Null
                _IsolationDisableAdapters | Out-Null
            }
        }
        # Rewrite state so adapter-list and lifeline IPs are fresh.
        _IsolationWriteState `
            -Level       $state.Level `
            -IsolatedAt  $state.IsolatedAt `
            -IsolatedBy  $state.IsolatedBy `
            -Reason      "$($state.Reason) (self-healed)" `
            -DeadlineAt  $state.DeadlineAt `
            -CommandId   $state.CommandId `
            -LifelineIps @($lifeline.ApiIp, $lifeline.WazuhIp)
    } catch {
        _IsolationLog "ERROR" "self-heal failed: $_"
    }
}

# Restore exactly the adapters in IsolationDisabledAdapters. Idempotent.
function _IsolationRestoreAdapters {
    try {
        $raw = (Get-ItemProperty -Path $RegPath -Name "IsolationDisabledAdapters" -ErrorAction SilentlyContinue).IsolationDisabledAdapters
        $names = @()
        if ($raw) { $names = @($raw) }
        foreach ($n in $names) {
            if ([string]::IsNullOrWhiteSpace($n)) { continue }
            try {
                Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction Stop
                _IsolationLog "INFO" "adapter-restore name='$n'"
            } catch {
                _IsolationLog "WARN" "adapter-restore failed name='$n': $_"
            }
        }
        Remove-ItemProperty -Path $RegPath -Name "IsolationDisabledAdapters" -ErrorAction SilentlyContinue
    } catch {
        _IsolationLog "WARN" "adapter-restore lookup failed: $_"
    }
}

# Atomic teardown -- removes every isolation artefact this script has ever
# created. Idempotent: safe to call when nothing is isolated.
function _IsolationTeardown {
    # 1. Restore profile defaults (inbound + outbound) if we saved them.
    try {
        $origRaw = (Get-ItemProperty -Path $RegPath -Name "IsolationOrigProfileDefaults" -ErrorAction SilentlyContinue).IsolationOrigProfileDefaults
        if ($origRaw) {
            $orig = ConvertFrom-Json $origRaw
            foreach ($p in @("Domain","Private","Public")) {
                $entry = $orig.$p
                # Back-compat with Phase 2's flat string format. New format
                # is @{outbound;inbound} per profile; old format is "<action>".
                if ($entry -is [string]) {
                    Set-NetFirewallProfile -Profile $p `
                        -DefaultOutboundAction $entry `
                        -ErrorAction SilentlyContinue
                } else {
                    # NOTE: avoid inline `if-as-expression` here. PS 5.1's
                    # parser intermittently mis-nests when an `if (..) {..}
                    # else {..}` appears inside a try block, throwing a
                    # misleading "Try statement is missing its Catch" at the
                    # next `}` boundary. Explicit if/else statements parse
                    # reliably on every PS version.
                    $out = "Allow"
                    if ($entry.outbound) { $out = $entry.outbound }
                    $inn = "Block"
                    if ($entry.inbound)  { $inn = $entry.inbound }
                    Set-NetFirewallProfile -Profile $p `
                        -DefaultOutboundAction $out `
                        -DefaultInboundAction  $inn `
                        -ErrorAction SilentlyContinue
                }
            }
            Remove-ItemProperty -Path $RegPath -Name "IsolationOrigProfileDefaults" -ErrorAction SilentlyContinue
        }
    } catch {
        _IsolationLog "WARN" "profile defaults restore failed: $_"
    }
    # 2. Delete every rule tagged APT-ISOLATE-*. The wildcard match in
    #    Get-NetFirewallRule operates on DisplayName, which is what we set.
    try {
        Get-NetFirewallRule -DisplayName "APT-ISOLATE-*" -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } catch {
        _IsolationLog "WARN" "rule teardown via NetSecurity failed: $_"
    }
    # 3. Re-enable adapters we disabled (Full level only writes the list;
    #    no-op for Light / Standard).
    _IsolationRestoreAdapters
    # NOTE: deadman unregister was MOVED OUT of teardown in 2026-06-01. Caller
    # (Invoke-PanicUnisolate / Invoke-Unisolate) decides whether to remove the
    # deadman based on _IsolationVerifyTeardown -- leaving the deadman armed
    # when teardown was incomplete is the safety net for partial-recovery.
    # See the LOUD comment above _IsolationDeadmanRetry.
}

# Pre-flight + post-apply lifeline reachability check.
function _IsolationVerifyLifeline {
    param($Lifeline)
    try {
        return [bool](Test-NetConnection -ComputerName $Lifeline.ApiIp -Port $Lifeline.ApiPort `
                        -InformationLevel Quiet -WarningAction SilentlyContinue)
    } catch {
        return $false
    }
}

# Post-apply block verification -- confirm a known-public destination is now
# unreachable. 1.1.1.1:443 is reliable, fast, and a deterministic non-LAN
# target. If this is somehow on a corporate LAN (unlikely), Phase 10 hardening
# adds a configurable override.
function _IsolationVerifyBlock {
    try {
        $reachable = [bool](Test-NetConnection -ComputerName "1.1.1.1" -Port 443 `
                            -InformationLevel Quiet -WarningAction SilentlyContinue)
        return -not $reachable
    } catch {
        return $true
    }
}

function _IsolationWriteState {
    param(
        [string]   $Level,
        [string]   $IsolatedAt,
        [string]   $IsolatedBy,
        [string]   $Reason,
        [string]   $DeadlineAt,
        [string]   $CommandId,
        [string[]] $LifelineIps
    )
    Set-ItemProperty -Path $RegPath -Name "IsolationLevel"      -Value $Level
    Set-ItemProperty -Path $RegPath -Name "IsolatedAt"          -Value $IsolatedAt
    Set-ItemProperty -Path $RegPath -Name "IsolatedBy"          -Value $IsolatedBy
    Set-ItemProperty -Path $RegPath -Name "IsolationReason"     -Value $Reason
    Set-ItemProperty -Path $RegPath -Name "IsolationDeadlineAt" -Value $DeadlineAt
    Set-ItemProperty -Path $RegPath -Name "IsolationCommandId"  -Value $CommandId
    New-ItemProperty -Path $RegPath -Name "IsolationLifelineIps" `
        -Value $LifelineIps -PropertyType MultiString -Force | Out-Null
}

function _IsolationReadState {
    try {
        $lvl = (Get-ItemProperty -Path $RegPath -Name "IsolationLevel" -ErrorAction Stop).IsolationLevel
        if ([string]::IsNullOrWhiteSpace($lvl)) { return $null }
    } catch { return $null }
    return @{
        Level      = $lvl
        IsolatedAt = (Get-ItemProperty -Path $RegPath -Name "IsolatedAt"          -ErrorAction SilentlyContinue).IsolatedAt
        IsolatedBy = (Get-ItemProperty -Path $RegPath -Name "IsolatedBy"          -ErrorAction SilentlyContinue).IsolatedBy
        Reason     = (Get-ItemProperty -Path $RegPath -Name "IsolationReason"     -ErrorAction SilentlyContinue).IsolationReason
        DeadlineAt = (Get-ItemProperty -Path $RegPath -Name "IsolationDeadlineAt" -ErrorAction SilentlyContinue).IsolationDeadlineAt
        CommandId  = (Get-ItemProperty -Path $RegPath -Name "IsolationCommandId"  -ErrorAction SilentlyContinue).IsolationCommandId
    }
}

function _IsolationClearState {
    foreach ($name in @(
        "IsolationLevel","IsolatedAt","IsolatedBy","IsolationReason",
        "IsolationDeadlineAt","IsolationCommandId","IsolationLifelineIps",
        "IsolationOrigProfileDefaults","IsolationDisabledAdapters"
    )) {
        Remove-ItemProperty -Path $RegPath -Name $name -ErrorAction SilentlyContinue
    }
}

# -- Whitelisted handlers ---------------------------------------------------

function Invoke-Isolate {
    param($Params, $Cmd)

    $level = ("$($Params.level)").ToLower()
    if ($level -notin @("light","standard","full")) {
        return @{ status = "rejected"; output = "Invalid level (need light|standard|full); got '$level'" }
    }

    # Param parsing with clamps.
    $ttlMin = 240
    if ($Params.ttl_minutes) { $ttlMin = [int]$Params.ttl_minutes }
    if ($ttlMin -lt 5)    { $ttlMin = 5 }
    if ($ttlMin -gt 1440) { $ttlMin = 1440 }
    $reason    = "$($Params.reason)"
    $commandId = if ($Cmd -and $Cmd.command_id) { "$($Cmd.command_id)" } else { "" }
    $issuedBy  = if ($Cmd -and $Cmd.issued_by)  { "$($Cmd.issued_by)"  } else { "server" }
    # Notification default: ON for all tiers (Light, Standard, Full). The user
    # gets up to three toasts per isolate: "received" -> "applied" or "failed".
    # The operator can opt OUT via params.notify=false (e.g. for a stealth
    # investigation where the user must not learn the device is under review).
    # The legacy params.toast is honoured as an alias for backwards compat.
    #
    # NOTE: previously Light suppressed all toasts by design ("user keeps
    # working unaware"). That stealth mode is still available via notify=false,
    # but is no longer the default -- the user explicitly requested visibility
    # at all tiers on 2026-05-31 so they could see lifecycle feedback.
    $notify = $true
    if ($Params.PSObject.Properties.Name -contains "notify") {
        $notify = [bool]$Params.notify
    } elseif ($Params.PSObject.Properties.Name -contains "toast") {
        $notify = [bool]$Params.toast
    }

    # 0. SYSTEM check -- firewall + profile writes require it.
    $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
    if ($me -ne "NT AUTHORITY\SYSTEM") {
        return @{ status = "rejected"; output = "must run as SYSTEM (current: $me)" }
    }

    # 1. Idempotency.
    $existing = _IsolationReadState
    if ($existing) {
        if ($existing.Level -eq $level) {
            return @{ status = "success"; output = "already isolated at level $level" }
        }
        return @{ status = "rejected"; output = "already isolated at level $($existing.Level); unisolate first" }
    }

    # 2. Resolve lifeline endpoints (IP literals).
    try {
        $lifeline = _IsolationResolveLifeline
    } catch {
        _IsolationLog "ERROR" "lifeline resolve failed: $_"
        return @{ status = "rejected"; output = "lifeline resolution failed: $_" }
    }

    # NOTIFY (1/3) -- "received". We're past param validation, SYSTEM check,
    # idempotency, and lifeline resolution. From here on we're committed to
    # attempting the apply, so the user should know.
    if ($notify) {
        _IsolationToastForLevel -Moment "received" -Level $level -Reason $reason
    }

    # 3. Pre-flight: refuse to isolate a host that already can't reach the
    #    platform -- otherwise we'd permanently strand it.
    if (-not (_IsolationVerifyLifeline $lifeline)) {
        if ($notify) {
            _IsolationToastForLevel -Moment "failed" -Level $level -Reason $reason `
                -Detail "Lifeline to platform unreachable before isolation; refusing to strand this device."
        }
        return @{ status = "rejected"; output = "lifeline unreachable before isolate; refusing to strand the host" }
    }

    # 4. Apply (lifeline first, then level-specific blocks, then Full-only
    #    adapter disable). Disable runs AFTER the post-apply verify in
    #    step 5 -- no point disabling a VPN if the firewall didn't take.
    $createdRules = @()
    try {
        $createdRules += _IsolationApplyLifeline $lifeline
        switch ($level) {
            "light"    { $createdRules += _IsolationApplyLight    $lifeline }
            "standard" { $createdRules += _IsolationApplyStandard $lifeline }
            "full"     { $createdRules += _IsolationApplyFull     $lifeline }
        }
    } catch {
        _IsolationLog "ERROR" "apply failed, rolling back: $_"
        _IsolationTeardown
        if ($notify) {
            _IsolationToastForLevel -Moment "failed" -Level $level -Reason $reason `
                -Detail "Firewall rule creation failed; previous state restored. ($_)"
        }
        return @{ status = "failure"; output = "apply failed, rolled back: $_" }
    }

    # 5. Post-apply verify -- lifeline still works.
    if (-not (_IsolationVerifyLifeline $lifeline)) {
        _IsolationTeardown
        if ($notify) {
            _IsolationToastForLevel -Moment "failed" -Level $level -Reason $reason `
                -Detail "Lifeline severed after applying rules; previous state restored."
        }
        return @{ status = "failure"; output = "lifeline severed after apply; rolled back" }
    }
    # Standard + Full also verify a known-public destination is now
    # unreachable. Light is intentionally permissive on the general internet
    # (it only blocks pivot ports + foreign DNS), so block-verify is N/A.
    $blockVerified = $true
    if ($level -in @("standard","full")) {
        $blockVerified = _IsolationVerifyBlock
        if (-not $blockVerified) {
            _IsolationTeardown
            if ($notify) {
                _IsolationToastForLevel -Moment "failed" -Level $level -Reason $reason `
                    -Detail "Block rules did not take effect (1.1.1.1:443 still reachable); previous state restored."
            }
            return @{ status = "failure"; output = "block not effective (1.1.1.1:443 still reachable); rolled back" }
        }
    }

    # 6. Full-only: disable virtual / VPN adapters so a tunnel can't bypass
    #    the firewall rules. Names persisted to registry before the disable
    #    runs -- crash-safe restoration.
    $adaptersDisabled = @()
    if ($level -eq "full") {
        $adaptersDisabled = @(_IsolationDisableAdapters)
        # Re-verify the lifeline survived the adapter shake-up (a Hyper-V
        # vSwitch that happens to be on the management path would break it).
        if (-not (_IsolationVerifyLifeline $lifeline)) {
            _IsolationRestoreAdapters
            _IsolationTeardown
            if ($notify) {
                _IsolationToastForLevel -Moment "failed" -Level $level -Reason $reason `
                    -Detail "Lifeline severed after disabling virtual adapters; previous state restored."
            }
            return @{ status = "failure"; output = "lifeline severed after adapter disable; rolled back" }
        }
    }

    # 7. Persist state for the next ISOLATE/UNISOLATE call + audit.
    $isolatedAtDt = (Get-Date).ToUniversalTime()
    $deadlineDt   = $isolatedAtDt.AddMinutes($ttlMin)
    $isolatedAt   = $isolatedAtDt.ToString("o")
    $deadlineAt   = $deadlineDt.ToString("o")
    _IsolationWriteState `
        -Level $level `
        -IsolatedAt $isolatedAt `
        -IsolatedBy $issuedBy `
        -Reason $reason `
        -DeadlineAt $deadlineAt `
        -CommandId $commandId `
        -LifelineIps @($lifeline.ApiIp, $lifeline.WazuhIp)

    # 7b. Register the deadman -- auto-unisolate at IsolatedAt + ttl_minutes
    #     if nothing has run UNISOLATE by then. If this fails we still leave
    #     the isolation in place + return success, but flag the failure in
    #     the result so the operator knows the safety net is missing.
    #     Reset any lingering DeadmanRetryCount from a previous incomplete
    #     recovery so this fresh isolate gets a full retry budget.
    Remove-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue
    $deadmanRegistered = $true
    try {
        _IsolationRegisterDeadman -DeadlineUtc $deadlineDt
    } catch {
        $deadmanRegistered = $false
        _IsolationLog "WARN" "deadman registration failed; isolation will persist until manual unisolate"
    }

    _IsolationLog "INFO" "isolated level=$level ttl_min=$ttlMin by=$issuedBy reason=$reason adapters=$($adaptersDisabled.Count) deadman=$deadmanRegistered"

    # NOTIFY (3/3) -- "applied". Tier-aware copy via _IsolationToastForLevel
    # so Light / Standard / Full each get an honest description of what the
    # user can and can't do now. The operator's free-text reason is appended
    # so the user has context ("Suspected credential theft on dc probe", etc.).
    if ($notify) {
        _IsolationToastForLevel -Moment "applied" -Level $level -Reason $reason
    }

    $resultObj = [ordered]@{
        level              = $level
        rules_created      = $createdRules
        adapters_disabled  = $adaptersDisabled
        deadline_at        = $deadlineAt
        lifeline_verified  = $true
        block_verified     = $blockVerified
        deadman_registered = $deadmanRegistered
        deadman_fired      = $false
    }
    return @{ status = "success"; output = (ConvertTo-Json $resultObj -Compress) }
}

# +==========================================================================+
# |  DEADMAN RESILIENCE MODEL  --  DO NOT WEAKEN WITHOUT READING THIS.       |
# +==========================================================================+
# |  The deadman scheduled task is the LAST automated recovery layer         |
# |  before manual on-host intervention. Its sole job: if nothing has lifted |
# |  isolation by the TTL, fire `-PanicUnisolate` and restore the host.      |
# |                                                                          |
# |  PRE-2026-06-01 behaviour was naive:                                     |
# |    1. Deadman fires -> calls _IsolationTeardown                          |
# |    2. Teardown silently swallows errors (-ErrorAction SilentlyContinue)  |
# |    3. Teardown unconditionally unregisters the deadman task as step 4    |
# |    4. Returned "success" even when firewall rules / adapters / profile   |
# |       defaults still wrong -> host stuck PARTIALLY isolated with no      |
# |       safety net armed.                                                  |
# |                                                                          |
# |  POST-2026-06-01 RESILIENT flow:                                         |
# |    1. Notify user "auto-recovery initiated" (if deadman-initiated)       |
# |    2. Run teardown (errors swallowed as before -- best-effort)           |
# |    3. VERIFY via _IsolationVerifyTeardown (5 checks: no APT-ISOLATE-*    |
# |       rules left, adapters Up, profile defaults != Block, registry       |
# |       cleared, internet reachable)                                       |
# |    4a. If verify OK: clear state, unregister deadman, notify user        |
# |        "network restored", return success                                |
# |    4b. If verify FAILED: LEAVE deadman armed for retry (bounded by       |
# |        DeadmanMaxRetries=3, re-fires in DeadmanRetryIntervalMin=5).      |
# |        Notify user "auto-recovery incomplete" with detail. Return        |
# |        failure with detail.                                              |
# |    4c. If retry cap reached: log ERROR, DO NOT re-arm (so an operator    |
# |        monitoring scheduled tasks notices it's gone), require manual     |
# |        recovery. The host's isolation state registry markers REMAIN,     |
# |        so a subsequent operator-issued UNISOLATE / panic-local also      |
# |        knows what level to tear down from.                               |
# |                                                                          |
# |  WHY KEEPING DEADMAN ON FAILURE IS LOAD-BEARING:                         |
# |    The whole point of the deadman is "the platform might be down /       |
# |    the agent might be broken / the operator might be asleep". If we      |
# |    remove it on a half-successful recovery, the host is back in the      |
# |    "no automated recovery layer" state that the deadman exists to        |
# |    prevent. Worse, the user sees "network restored" toast even though    |
# |    they're still stuck -- a confusing failure mode.                      |
# |                                                                          |
# |  TIME COST: _IsolationVerifyTeardown's Test-NetConnection 1.1.1.1        |
# |    takes ~21s on TCP timeout (when verify fails) and ~50ms on success.   |
# |    Worst case: 21s added to the deadman fire -- acceptable for a path    |
# |    that runs at most every TTL.                                          |
# +==========================================================================+

# Bounded retry constants for the deadman re-arm path.
$DeadmanMaxRetries        = 3
$DeadmanRetryIntervalMin  = 5

# Verify the host is back to a usable state after a teardown attempt.
# Returns @{ ok = bool; issues = [string[]] }. Used by Invoke-PanicUnisolate
# and Invoke-Unisolate to decide whether to remove the deadman safety net.
function _IsolationVerifyTeardown {
    $issues = @()

    # 1. No APT-ISOLATE-* firewall rules remain (rule teardown actually took).
    try {
        $remaining = @(Get-NetFirewallRule -DisplayName "APT-ISOLATE-*" -ErrorAction SilentlyContinue)
        if ($remaining.Count -gt 0) {
            $issues += ("{0} APT-ISOLATE-* firewall rule(s) still present" -f $remaining.Count)
        }
    } catch {
        $issues += "could not enumerate firewall rules: $_"
    }

    # 2. Every adapter we disabled (Full level only) is now Up. Skip if the
    #    registry value is gone (RestoreAdapters successfully cleared it).
    try {
        $rawDisabled = (Get-ItemProperty -Path $RegPath -Name "IsolationDisabledAdapters" -ErrorAction SilentlyContinue).IsolationDisabledAdapters
        if ($rawDisabled) {
            foreach ($n in @($rawDisabled)) {
                if ([string]::IsNullOrWhiteSpace($n)) { continue }
                $adp = Get-NetAdapter -Name $n -ErrorAction SilentlyContinue
                if ($adp -and $adp.Status -ne "Up") {
                    $issues += ("adapter '{0}' is {1}, expected Up" -f $n, $adp.Status)
                }
            }
        }
    } catch {
        $issues += "could not check adapter state: $_"
    }

    # 3. Profile defaults restored -- not stuck at Block. We don't enforce a
    #    specific value (Allow is the Windows default for outbound; the
    #    original might have been Block in a hardened environment), only
    #    flag the case where we left the system worse than we found it.
    try {
        foreach ($p in @("Domain","Private","Public")) {
            $prof = Get-NetFirewallProfile -Profile $p -ErrorAction SilentlyContinue
            if ($prof -and $prof.DefaultOutboundAction -eq "Block") {
                # Only count this as an issue if WE were the ones who set it
                # (IsolationOrigProfileDefaults absent means restore ran).
                $origStillSet = (Get-ItemProperty -Path $RegPath -Name "IsolationOrigProfileDefaults" -ErrorAction SilentlyContinue).IsolationOrigProfileDefaults
                if ($origStillSet) {
                    $issues += ("profile '{0}' still has DefaultOutboundAction=Block (restore did not run)" -f $p)
                }
            }
        }
    } catch {
        $issues += "could not check firewall profile defaults: $_"
    }

    # 4. Internet actually reachable. Definitive proof the host is recovered
    #    from the user's perspective. Long timeout (~21s) on failure but
    #    acceptable for a path that runs once per deadman fire.
    try {
        $reach = [bool](Test-NetConnection -ComputerName "1.1.1.1" -Port 443 `
                        -InformationLevel Quiet -WarningAction SilentlyContinue)
        if (-not $reach) {
            $issues += "public internet (1.1.1.1:443) still unreachable"
        }
    } catch {
        $issues += "internet reachability probe failed: $_"
    }

    return @{ ok = ($issues.Count -eq 0); issues = $issues }
}

# Re-arm the deadman for a short retry when teardown verification failed.
# Bounded by DeadmanMaxRetries. Returns $true if re-armed, $false if cap
# reached (caller should NOT explicitly unregister -- leaving the deadman
# GONE signals "manual recovery required" to whoever's watching the task
# list). The retry counter resets when an isolate command succeeds OR when
# a verified teardown completes.
function _IsolationDeadmanRetry {
    try {
        $count = 0
        $raw = (Get-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue).IsolationDeadmanRetryCount
        if ($raw) { $count = [int]$raw }
        $count++
        if ($count -gt $DeadmanMaxRetries) {
            _IsolationLog "ERROR" "deadman retry cap reached ($DeadmanMaxRetries); giving up -- MANUAL RECOVERY REQUIRED"
            return $false
        }
        $nextFire = (Get-Date).AddMinutes($DeadmanRetryIntervalMin).ToUniversalTime()
        _IsolationRegisterDeadman -DeadlineUtc $nextFire
        Set-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -Value $count
        _IsolationLog "INFO" ("deadman re-armed for retry {0}/{1} at {2}Z" -f $count, $DeadmanMaxRetries, $nextFire.ToString('s'))
        return $true
    } catch {
        _IsolationLog "ERROR" "deadman retry re-registration failed: $_"
        return $false
    }
}

# Tier-aware toast copy for the three deadman recovery moments. Separate
# from _IsolationToastForLevel (which covers isolate apply) because the
# audience expectation is different: at apply-time the user expects
# something to happen; at recovery-time the user has often forgotten the
# device was even isolated.
function _IsolationToastForRecovery {
    param(
        [ValidateSet("triggered","restored","incomplete")] [string]$Moment,
        [ValidateSet("light","standard","full")]           [string]$Level,
        [string]$Reason = "",
        [string]$Detail = ""
    )
    $title = ""; $body = ""; $icon = "Information"
    switch ($Moment) {
        "triggered" {
            $icon  = "Information"
            $title = "Auto-recovery initiated"
            $body  = "The security platform did not lift this device's restrictions before the timeout. Auto-recovery is running now to restore network access."
        }
        "restored" {
            $icon  = "Information"
            $title = "Network access restored"
            switch ($Level) {
                "light"    { $body = "The security review on this device has been lifted. Full network access is restored." }
                "standard" { $body = "Quarantine has been lifted on this device. Full network access is restored." }
                "full"     { $body = "Isolation has been lifted on this device. Full network access is restored." }
            }
        }
        "incomplete" {
            $icon  = "Stop"
            $title = "Auto-recovery incomplete"
            $body  = "Some restrictions could not be removed automatically. The platform will retry within a few minutes. If network access is still limited after 15 minutes, please contact IT."
            if (-not [string]::IsNullOrWhiteSpace($Detail)) {
                $cleanDetail = ($Detail -replace "[\r\n\t]+", " ").Trim()
                if ($cleanDetail.Length -gt 200) { $cleanDetail = $cleanDetail.Substring(0,197) + "..." }
                $body = "$body`n`nDetail: $cleanDetail"
            }
        }
    }
    _IsolationToast -Title $title -Body $body -Reason $Reason -Icon $icon
}

function Invoke-PanicUnisolate {
    param([string]$Reason)
    $existing = _IsolationReadState
    if (-not $existing) {
        # Already clear. Scrub any orphan deadman so it doesn't fire later on
        # a clean host (and reset the retry counter if it lingered).
        _IsolationUnregisterDeadman
        Remove-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue
        _IsolationLog "INFO" "panic-unisolate: not isolated; no-op (deadman scrubbed)"
        return @{ status = "success"; output = "not isolated; no-op" }
    }

    $level     = $existing.Level
    $isDeadman = ($Reason -like "deadman:*")

    # NOTIFY (triggered) -- fires only when the deadman initiated this. Operator-
    # initiated panic-local is being run by an admin who already knows.
    if ($isDeadman) {
        _IsolationToastForRecovery -Moment "triggered" -Level $level -Reason $Reason
    }

    # Best-effort teardown. Errors are logged inside but don't propagate --
    # the source of truth is _IsolationVerifyTeardown below.
    try {
        _IsolationTeardown
    } catch {
        _IsolationLog "ERROR" "panic-unisolate teardown threw: $_"
    }

    # VERIFY before deciding what to do with the deadman.
    $v = _IsolationVerifyTeardown
    if ($v.ok) {
        # Clean recovery. Persist panic markers BEFORE clearing the level
        # registry so the next successful poll can back-report this event.
        Set-ItemProperty -Path $RegPath -Name "IsolationPanicReason"    -Value $Reason
        Set-ItemProperty -Path $RegPath -Name "IsolationPanicAt"        -Value (Get-Date).ToUniversalTime().ToString("o")
        Set-ItemProperty -Path $RegPath -Name "IsolationPanicLastLevel" -Value $level
        _IsolationClearState
        _IsolationUnregisterDeadman
        Remove-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue
        _IsolationLog "INFO" "panic-unisolated from level=$level reason=$Reason (verified clean)"
        if ($isDeadman) {
            _IsolationToastForRecovery -Moment "restored" -Level $level -Reason $Reason
        }
        return @{ status = "success"; output = "panic-unisolated from $level (verified)" }
    }

    # VERIFICATION FAILED. Host is partially un-isolated. Re-arm the deadman
    # for retry. Keep the IsolationLevel registry so a subsequent teardown
    # attempt knows what level to clean up. Notify user.
    $issueStr = ($v.issues -join "; ")
    _IsolationLog "WARN" "panic-unisolate verification FAILED: $issueStr"
    $reArmed = _IsolationDeadmanRetry

    if ($isDeadman) {
        _IsolationToastForRecovery -Moment "incomplete" -Level $level -Reason $Reason -Detail $issueStr
    }

    $msg = "teardown verification failed: $issueStr"
    if ($reArmed) {
        $msg = "$msg (deadman re-armed for retry; will try again in ${DeadmanRetryIntervalMin} min)"
    } else {
        $msg = "$msg (retry cap reached; MANUAL RECOVERY REQUIRED)"
    }
    return @{ status = "failure"; output = $msg }
}

function Invoke-Unisolate {
    param($Params, $Cmd)
    $reason   = "$($Params.reason)"
    $existing = _IsolationReadState
    if (-not $existing) {
        # Already clear. Scrub any orphan deadman so it doesn't fire later.
        _IsolationUnregisterDeadman
        Remove-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue
        return @{ status = "success"; output = "not isolated; no-op" }
    }
    $level = $existing.Level

    # Best-effort teardown. Errors logged inside; verification below is truth.
    try {
        _IsolationTeardown
    } catch {
        _IsolationLog "ERROR" "unisolate teardown threw: $_"
    }

    # VERIFY before declaring success and removing the deadman safety net.
    # If the host isn't actually clean, LEAVE THE DEADMAN ARMED -- it's the
    # only automated recovery layer remaining. The operator can re-issue
    # UNISOLATE manually after diagnosing whatever blocked the teardown.
    $v = _IsolationVerifyTeardown
    if (-not $v.ok) {
        $issueStr = ($v.issues -join "; ")
        _IsolationLog "WARN" "unisolate verification FAILED: $issueStr (deadman LEFT IN PLACE as safety net)"
        _IsolationToastForRecovery -Moment "incomplete" -Level $level -Reason $reason -Detail $issueStr
        return @{ status = "failure"; output = "teardown verification failed: $issueStr (deadman retained)" }
    }

    # Clean. Clear state, remove the deadman, reset retry counter.
    _IsolationClearState
    _IsolationUnregisterDeadman
    Remove-ItemProperty -Path $RegPath -Name "IsolationDeadmanRetryCount" -ErrorAction SilentlyContinue
    _IsolationLog "INFO" "unisolated from level=$level reason=$reason (verified clean)"

    # Mirror the apply-time toast: tell the user when network is back. All
    # tiers -- Light included -- per the 2026-05-31 visibility decision.
    _IsolationToastForRecovery -Moment "restored" -Level $level -Reason $reason

    $resultObj = [ordered]@{
        unisolated_from = $level
        reason          = $reason
    }
    return @{ status = "success"; output = (ConvertTo-Json $resultObj -Compress) }
}

# ===========================================================================
#                          HANDLER SELF-UPDATE (OTA)
# ===========================================================================
# Auto-pull at the top of every poll. The agent fetches a tiny manifest
# (version + sha256) over the existing HMAC-authenticated /agents/{id}/...
# channel, compares to its registry-tracked HandlerVersion, and only
# downloads + applies a new script when they differ.
#
# Layout on disk (under $ScriptDir, default ProgramData\APTPlatform):
#   agent_command_handler.ps1       <- live, what Task Scheduler launches
#   agent_command_handler.ps1.bak   <- previous version, used by rollback
#   agent_command_handler.ps1.new   <- staging during apply (briefly only)
#
# Registry crumbs under HKLM:\SOFTWARE\APTPlatform:
#   HandlerVersion       current live version label
#   HandlerSha256        sha256 of the live script
#   HandlerInstalledAt   ISO8601 UTC
#   HandlerPrevVersion   what's in the .bak (or "" if no .bak yet)
#
# Hot-swap safety: PowerShell loads the script into memory at task launch
# and closes the file handle, so replacing the file mid-iteration is safe.
# The currently-running poll finishes with OLD code in memory; the next
# scheduled-task tick (within 60 s) reads the new file.
# ===========================================================================

function _HandlerLivePath { return (Join-Path $ScriptDir "agent_command_handler.ps1") }
function _HandlerBakPath  { return (Join-Path $ScriptDir "agent_command_handler.ps1.bak") }
function _HandlerNewPath  { return (Join-Path $ScriptDir "agent_command_handler.ps1.new") }

# Compute hex SHA-256 of a UTF-8 string. Used to verify the bytes the server
# returned match the manifest's sha256 BEFORE we touch disk.
function _HandlerSha256 {
    param([string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString("x2") })
    } finally { $sha.Dispose() }
}

# Fetch + verify + atomic-replace. Used by both the auto-pull path
# (_HandlerSelfUpdate) and the explicit operator-push command
# (Invoke-UpdateHandler). Throws on any verification failure; the caller
# decides whether that's a return-rejected or just-skip-this-cycle.
function _HandlerFetchAndApply {
    param(
        [Parameter(Mandatory=$true)] [string]$Version,
        [Parameter(Mandatory=$true)] [string]$ExpectedSha256
    )
    # 1. Fetch -- same HMAC auth as poll. Use Invoke-WebRequest so we can
    #    read the X-Handler-SHA256 response header as a redundancy check
    #    against the manifest value.
    $resp = Invoke-WebRequest -Method Get `
        -Uri "$ServerUrl/agents/$AgentId/handler/content?version=$Version" `
        -Headers @{ "Authorization" = (Get-AuthHeader) } `
        -TimeoutSec 30 -UseBasicParsing
    $content = $resp.Content
    if (-not $content -or $content.Length -lt 200) {
        throw "handler content suspiciously small ($($content.Length) bytes)"
    }

    # 2. Verify SHA-256 against the manifest value AND the response header.
    $localSha = _HandlerSha256 $content
    $expected = $ExpectedSha256.ToLower()
    if ($localSha -ne $expected) {
        throw "SHA-256 mismatch (got $localSha, manifest expected $expected)"
    }
    $hdrSha = ($resp.Headers["X-Handler-SHA256"]) | Select-Object -First 1
    if ($hdrSha -and $hdrSha.ToLower() -ne $expected) {
        throw "X-Handler-SHA256 header disagrees with manifest"
    }

    # 3. Syntax-validate. If PS can't parse the script, do NOT replace --
    #    we'd just brick the next tick. Wrap in a try so the parser error
    #    becomes a clean handler-side exception.
    try {
        [scriptblock]::Create($content) | Out-Null
    } catch {
        throw "handler script failed PS syntax check: $_"
    }

    # 4. Atomic replace: write to .new, rotate .bak <- live, live <- .new.
    $live = _HandlerLivePath
    $bak  = _HandlerBakPath
    $new  = _HandlerNewPath
    #
    # +======================================================================+
    # |  DOUBLE-BOM TRAP  --  DO NOT REPLACE WITH Set-Content -Encoding utf8 |
    # +======================================================================+
    # |  Set-Content -Encoding utf8 UNCONDITIONALLY prepends a UTF-8 BOM     |
    # |  to its output. Our $content was read from Invoke-WebRequest, which  |
    # |  on PS 5.1 does NOT strip the BOM -- it preserves it as the leading  |
    # |  <BOM> character of the string. Routing through Set-Content          |
    # |  therefore produces a DOUBLE-BOM file on disk:                       |
    # |      EF BB BF  EF BB BF  # scripts/...                               |
    # |                                                                      |
    # |  Symptom: first BOM is consumed as the encoding marker; the second   |
    # |  BOM becomes a <BOM> "command" on line 1, throwing a NON-FATAL       |
    # |  parse error. Normal polling tolerates this. But ANY invocation      |
    # |  passing switch arguments (e.g. the deadman's -PanicUnisolate        |
    # |  -Reason "deadman:ttl-expired") gets a param-binding failure         |
    # |  because the corrupted preamble confuses the binder -- the script    |
    # |  silently exits 0 without ever running Invoke-PanicUnisolate.        |
    # |                                                                      |
    # |  Net effect for nearly TWO MONTHS until 2026-06-02: every deadman    |
    # |  fire silently no-op'd, leaving isolated endpoints stranded until    |
    # |  manual recovery. Polling worked the whole time, so the bug never    |
    # |  surfaced in normal operation.                                       |
    # |                                                                      |
    # |  The fix: write raw bytes via [System.IO.File]::WriteAllBytes. The   |
    # |  bytes are exactly what we just hashed in step 2 (same Encoding-     |
    # |  GetBytes path) -- guaranteed single-BOM, guaranteed Get-FileHash    |
    # |  matches the manifest SHA, guaranteed PS 5.1 reads it cleanly.       |
    # |                                                                      |
    # |  Do NOT replace this with Set-Content / Out-File / Add-Content with  |
    # |  -Encoding utf8 ever. If you must use a cmdlet, use                  |
    # |  [System.IO.File]::WriteAllText or pre-strip the BOM from $content.  |
    # +======================================================================+
    $writeBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    [System.IO.File]::WriteAllBytes($new, $writeBytes)
    if (Test-Path $bak) { Remove-Item $bak -Force -ErrorAction SilentlyContinue }
    if (Test-Path $live) { Move-Item $live $bak -Force }
    Move-Item $new $live -Force

    # +======================================================================+
    # |  POST-WRITE VERIFICATION  --  three layered checks + auto-rollback   |
    # +======================================================================+
    # |  All prior safety checks operated on the in-memory $content string.  |
    # |  The 2026-06-02 double-BOM incident proved that mutations BETWEEN    |
    # |  memory and disk (Set-Content prepending a BOM, future encoding      |
    # |  changes, etc.) can produce a file that hashes correctly in memory   |
    # |  but parses incorrectly when next loaded by powershell.exe. Without  |
    # |  reading the file back we'd never know -- until the deadman's        |
    # |  switch-arg invocation hit a param-binding failure WEEKS later.      |
    # |                                                                      |
    # |  These three checks read the file BACK FROM DISK and validate it     |
    # |  the way the scheduled task will load it:                            |
    # |    A. Get-FileHash matches the manifest sha (catches any byte        |
    # |       mutation between memory and disk -- the double-BOM case)       |
    # |    B. [scriptblock]::Create reads the FILE (not the string) -- proves|
    # |       the file's encoding/line-endings parse cleanly                 |
    # |    C. Spawn powershell.exe -File <new> -SelfTest -- proves switch-   |
    # |       arg invocation works end-to-end (catches the deadman bug       |
    # |       directly -- was the missing layer that hid the BOM issue)      |
    # |                                                                      |
    # |  Any failure triggers an atomic rollback: the broken NEW file is     |
    # |  preserved at $live.failed-<unix> for forensics, .bak is restored    |
    # |  to $live, and the agent continues running the LAST KNOWN GOOD       |
    # |  version. The failure is recorded in registry markers (HandlerUpdate*) |
    # |  and surfaced to the server via the next heartbeat.                  |
    # |                                                                      |
    # |  These checks add ~2-3s per OTA. They run AFTER the atomic swap so   |
    # |  we measure the EXACT bytes the next scheduled-task invocation will  |
    # |  load.                                                               |
    # |                                                                      |
    # |  DO NOT REMOVE. DO NOT SKIP IN "SIMPLE" PATHS.                       |
    # +======================================================================+

    $verifyOk     = $true
    $verifyDetail = ""

    # Check A -- on-disk sha matches manifest.
    try {
        $diskSha = (Get-FileHash $live -Algorithm SHA256).Hash.ToLower()
        if ($diskSha -ne $expected) {
            $verifyOk = $false
            $verifyDetail = "sha_mismatch: on-disk=$diskSha expected=$expected"
        }
    } catch {
        $verifyOk = $false
        $verifyDetail = "sha_check_threw: $_"
    }

    # Check B -- file parses cleanly when read back from disk.
    if ($verifyOk) {
        try {
            $diskText = Get-Content -Path $live -Raw -ErrorAction Stop
            $null = [scriptblock]::Create($diskText)
        } catch {
            $verifyOk = $false
            $verifyDetail = "parse_failed: $_"
        }
    }

    # Check C -- switch-arg invocation works (the deadman's pattern).
    # NoProfile so $PROFILE doesn't taint the test. Bypass since the host's
    # ExecutionPolicy may be Restricted (Tanzania default).
    if ($verifyOk) {
        try {
            $selfTestOut  = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $live -SelfTest 2>&1
            $selfTestExit = $LASTEXITCODE
            $selfTestStr  = ("$selfTestOut").Trim()
            if ($selfTestExit -ne 0 -or $selfTestStr -notmatch "SELFTEST_OK") {
                $verifyOk = $false
                $clip = if ($selfTestStr.Length -gt 200) { $selfTestStr.Substring(0,197) + "..." } else { $selfTestStr }
                $verifyDetail = "invoke_failed: exit=$selfTestExit output='$clip'"
            }
        } catch {
            $verifyOk = $false
            $verifyDetail = "invoke_threw: $_"
        }
    }

    if (-not $verifyOk) {
        # -- ROLLBACK ------------------------------------------------------
        Write-Log "ERROR" "OTA post-write verify FAILED: $verifyDetail"
        $stamp     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $failedAt  = "$live.failed-$stamp"
        try {
            Move-Item $live $failedAt -Force -ErrorAction Stop
            if (Test-Path $bak) {
                # Copy (not move) so .bak stays as a rollback source for any
                # future failed OTA before another successful one repopulates it.
                Copy-Item $bak $live -Force -ErrorAction Stop
                Write-Log "INFO" "OTA rolled back: bad file preserved at $failedAt, live restored from .bak"
            } else {
                # Edge case: first-ever OTA failed, no .bak. The agent will
                # have NO handler script at all until manual recovery. Restore
                # the bad file so at least polling resumes; mark it failed.
                Move-Item $failedAt $live -Force -ErrorAction SilentlyContinue
                Write-Log "WARN" "OTA rollback: no .bak to restore; agent stays on potentially broken version"
            }
        } catch {
            Write-Log "ERROR" "OTA rollback FAILED: $_ (agent may be in an undefined state)"
        }

        # Persist failure status so heartbeat can report it to the server.
        # Use a short status code so the dashboard pill can map it.
        $statusCode = "rolled_back"
        if     ($verifyDetail -like "sha_mismatch:*")  { $statusCode = "sha_mismatch" }
        elseif ($verifyDetail -like "parse_failed:*")  { $statusCode = "parse_failed" }
        elseif ($verifyDetail -like "invoke_failed:*") { $statusCode = "invoke_failed" }
        Set-ItemProperty -Path $RegPath -Name "HandlerUpdateStatus"  -Value $statusCode
        Set-ItemProperty -Path $RegPath -Name "HandlerUpdateDetail"  -Value $verifyDetail
        Set-ItemProperty -Path $RegPath -Name "HandlerUpdateAt"      -Value (Get-Date).ToUniversalTime().ToString("o")
        Set-ItemProperty -Path $RegPath -Name "HandlerUpdateBadVer"  -Value $Version
        # Do NOT update HandlerVersion / HandlerSha256 -- those still reflect
        # the LAST KNOWN GOOD version that's now back at $live.
        throw "OTA post-write verify failed [$statusCode]: $verifyDetail"
    }

    # -- All three checks passed. Update registry crumbs to reflect new ver.
    $prevVer = (Get-ItemProperty -Path $RegPath -Name "HandlerVersion" -ErrorAction SilentlyContinue).HandlerVersion
    Set-ItemProperty -Path $RegPath -Name "HandlerVersion"      -Value $Version
    Set-ItemProperty -Path $RegPath -Name "HandlerSha256"       -Value $expected
    Set-ItemProperty -Path $RegPath -Name "HandlerInstalledAt"  -Value (Get-Date).ToUniversalTime().ToString("o")
    if ($prevVer) {
        Set-ItemProperty -Path $RegPath -Name "HandlerPrevVersion" -Value $prevVer
    }
    # Clear any prior failure markers -- a successful update supersedes them.
    Set-ItemProperty -Path $RegPath -Name "HandlerUpdateStatus" -Value "ok"
    foreach ($n in @("HandlerUpdateDetail","HandlerUpdateBadVer")) {
        Remove-ItemProperty -Path $RegPath -Name $n -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path $RegPath -Name "HandlerUpdateAt" -Value (Get-Date).ToUniversalTime().ToString("o")
    Write-Log "INFO" "Handler updated $prevVer -> $Version (sha256=$expected) [verified: sha+parse+selftest]"
}

# Top-of-poll auto-update check. Best-effort: if the manifest fetch fails
# (network blip, server reboot), we log and continue with the existing
# handler. The next tick will retry.
function _HandlerSelfUpdate {
    try {
        $manifest = Invoke-RestMethod -Method Get `
            -Uri "$ServerUrl/agents/$AgentId/handler/manifest" `
            -Headers @{ "Authorization" = (Get-AuthHeader) } `
            -TimeoutSec 10 -UseBasicParsing
    } catch {
        Write-Log "WARN" "Handler manifest check failed: $_"
        return
    }
    if (-not $manifest.version) {
        # Server has no live handler yet (nothing uploaded / promoted).
        return
    }
    $currentVer = (Get-ItemProperty -Path $RegPath -Name "HandlerVersion" -ErrorAction SilentlyContinue).HandlerVersion
    if ($currentVer -eq $manifest.version) { return }   # already on latest
    Write-Log "INFO" "Handler self-update: $currentVer -> $($manifest.version)"
    try {
        _HandlerFetchAndApply -Version $manifest.version -ExpectedSha256 $manifest.sha256
    } catch {
        Write-Log "ERROR" "Handler self-update failed (keeping current version): $_"
    }
}

# Operator-targeted push. Server enqueues `update_handler {version}` and
# the agent applies. Identical apply path to the auto-pull but explicit
# version + result-reporting via the command channel.
function Invoke-UpdateHandler {
    param($Params, $Cmd)
    $version = "$($Params.version)"
    if ([string]::IsNullOrWhiteSpace($version)) {
        return @{ status = "rejected"; output = "param 'version' required" }
    }
    # Resolve the expected SHA-256 from the manifest for THIS version.
    try {
        $manifest = Invoke-RestMethod -Method Get `
            -Uri "$ServerUrl/agents/$AgentId/handler/manifest?version=$version" `
            -Headers @{ "Authorization" = (Get-AuthHeader) } `
            -TimeoutSec 10 -UseBasicParsing
    } catch {
        return @{ status = "failure"; output = "manifest fetch failed: $_" }
    }
    if (-not $manifest.version -or $manifest.version -ne $version) {
        return @{ status = "rejected"; output = "version '$version' not found on server" }
    }
    try {
        _HandlerFetchAndApply -Version $manifest.version -ExpectedSha256 $manifest.sha256
        return @{ status = "success"; output = "applied $($manifest.version)" }
    } catch {
        return @{ status = "failure"; output = "$_" }
    }
}

# Swap live <-> .bak. One-deep rollback only; multi-step rollback requires
# operator to re-push the desired older version from the server's archive.
function Invoke-RollbackHandler {
    param($Params, $Cmd)
    $live = _HandlerLivePath
    $bak  = _HandlerBakPath
    if (-not (Test-Path $bak)) {
        return @{ status = "rejected"; output = "no .bak file available to roll back to" }
    }
    $reason = "$($Params.reason)"
    $prevVer = (Get-ItemProperty -Path $RegPath -Name "HandlerPrevVersion" -ErrorAction SilentlyContinue).HandlerPrevVersion
    $curVer  = (Get-ItemProperty -Path $RegPath -Name "HandlerVersion"     -ErrorAction SilentlyContinue).HandlerVersion
    # Three-way rename for atomic swap.
    $swap = "$live.swap"
    Move-Item $live $swap -Force
    Move-Item $bak  $live -Force
    Move-Item $swap $bak -Force
    # Flip the registry crumbs.
    if ($prevVer) {
        Set-ItemProperty -Path $RegPath -Name "HandlerVersion" -Value $prevVer
    } else {
        Remove-ItemProperty -Path $RegPath -Name "HandlerVersion" -ErrorAction SilentlyContinue
    }
    if ($curVer) {
        Set-ItemProperty -Path $RegPath -Name "HandlerPrevVersion" -Value $curVer
    }
    Set-ItemProperty -Path $RegPath -Name "HandlerInstalledAt" -Value (Get-Date).ToUniversalTime().ToString("o")
    Write-Log "INFO" "Handler rolled back $curVer -> $prevVer (reason=$reason)"
    return @{
        status = "success"
        output = (ConvertTo-Json @{
            from = $curVer
            to   = $prevVer
            reason = $reason
        } -Compress)
    }
}

# -- Dispatch table - WHITELIST ---------------------------------------------
$Handlers = @{
    "set_profile"      = ${function:Invoke-SetProfile}
    "toggle_telemetry" = ${function:Invoke-ToggleTelemetry}
    "restart_services" = ${function:Invoke-RestartServices}
    "get_status"       = ${function:Invoke-GetStatus}
    "update_sysmon"    = ${function:Invoke-UpdateSysmon}
    "isolate"          = ${function:Invoke-Isolate}
    "unisolate"        = ${function:Invoke-Unisolate}
    "update_handler"   = ${function:Invoke-UpdateHandler}
    "rollback_handler" = ${function:Invoke-RollbackHandler}
}

# -- Send result back to server ---------------------------------------------

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

# -- Heartbeat ---------------------------------------------------------------
# Sent at the end of every poll iteration. Carries the agent's current
# operational status so the dashboard / mobile fleet view reflects
# isolation + panic-recovery without depending on a successful command result
# round-trip. Failure is silent -- heartbeat is informational, not consensus.

function Send-Heartbeat {
    param([string]$Status, [string]$Profile = $null)
    $bodyObj = @{ status = $Status }
    if ($Profile) { $bodyObj.profile = $Profile }
    # Report the installed handler version so the dashboard's Fleet table
    # can flag out-of-date endpoints. NULL on a brand-new install before
    # the first manifest poll completes -- server treats null as "unknown".
    $handlerVer = (Get-ItemProperty -Path $RegPath -Name "HandlerVersion" -ErrorAction SilentlyContinue).HandlerVersion
    if ($handlerVer) { $bodyObj.handler_version = $handlerVer }
    # Report the OTA update status so the dashboard surfaces failed updates
    # instead of silently showing the old version. Status codes:
    #   "ok"            -- last OTA verified clean (or never attempted)
    #   "sha_mismatch"  -- on-disk bytes don't match manifest sha (write corruption)
    #   "parse_failed"  -- file fails [scriptblock]::Create read-back test
    #   "invoke_failed" -- -SelfTest invocation failed (param-binding etc.)
    #   "rolled_back"   -- generic failure, rolled back to .bak
    # Old server build (no field in HeartbeatBody) tolerates the extra key --
    # Pydantic config silently drops unknown fields.
    $updStatus = (Get-ItemProperty -Path $RegPath -Name "HandlerUpdateStatus" -ErrorAction SilentlyContinue).HandlerUpdateStatus
    if ($updStatus) { $bodyObj.handler_update_status = $updStatus }
    $updDetail = (Get-ItemProperty -Path $RegPath -Name "HandlerUpdateDetail" -ErrorAction SilentlyContinue).HandlerUpdateDetail
    if ($updDetail) {
        # Cap to keep heartbeats small; full detail is in registry on-host
        # for forensic inspection.
        if ($updDetail.Length -gt 240) { $updDetail = $updDetail.Substring(0,237) + "..." }
        $bodyObj.handler_update_detail = $updDetail
    }
    $updBadVer = (Get-ItemProperty -Path $RegPath -Name "HandlerUpdateBadVer" -ErrorAction SilentlyContinue).HandlerUpdateBadVer
    if ($updBadVer) { $bodyObj.handler_update_bad_version = $updBadVer }
    $body = ConvertTo-Json $bodyObj -Compress
    try {
        Invoke-RestMethod -Method Post `
            -Uri "$ServerUrl/agents/$AgentId/heartbeat" `
            -Headers @{ "Authorization" = (Get-AuthHeader); "Content-Type" = "application/json" } `
            -Body $body -TimeoutSec 15 -UseBasicParsing | Out-Null
    } catch {
        Write-Log "WARN" "Heartbeat failed: $_"
    }
}

# Resolve the status string this agent should report in its next heartbeat.
# Reads (and consumes) the panic marker if present so it back-reports once.
function Get-HeartbeatStatus {
    try {
        $panicReason = (Get-ItemProperty -Path $RegPath -Name "IsolationPanicReason"    -ErrorAction SilentlyContinue).IsolationPanicReason
        $panicLevel  = (Get-ItemProperty -Path $RegPath -Name "IsolationPanicLastLevel" -ErrorAction SilentlyContinue).IsolationPanicLastLevel
        if ($panicReason) {
            # Clear the marker after we capture it so we only back-report once.
            foreach ($n in @("IsolationPanicReason","IsolationPanicAt","IsolationPanicLastLevel")) {
                Remove-ItemProperty -Path $RegPath -Name $n -ErrorAction SilentlyContinue
            }
            # Explicit if/else inside try (PS 5.1 parser hardening).
            $lvl = "unknown"
            if ($panicLevel) { $lvl = $panicLevel }
            $rsn = ($panicReason -replace "[|:]","-")  # don't collide with our separator
            return "panic-unisolated:${lvl}:${rsn}"
        }
    } catch { }
    $st = _IsolationReadState
    if ($st) { return "isolated:$($st.Level)" }
    return "ok"
}

# ===========================================================================
#                              PANIC-LOCAL ENTRY POINT
# ===========================================================================
# Bypasses the poll loop entirely. Runs the local teardown and exits.
# The next normal poll iteration (next 60s tick) will back-report via the
# heartbeat's `panic-unisolated:<level>:<reason>` status string.

if ($PanicUnisolate) {
    Write-Log "INFO" "PanicUnisolate invoked (reason=$Reason)"
    try {
        $result = Invoke-PanicUnisolate -Reason $Reason
        Write-Log "INFO" ("Panic result: {0} - {1}" -f $result.status, $result.output)
        if ($result.status -ne "success") { exit 1 }
        exit 0
    } catch {
        Write-Log "ERROR" "PanicUnisolate raised: $_"
        exit 1
    }
}

# ===========================================================================
#                              MAIN POLL LOOP
# ===========================================================================

try {
    # Clock-skew self-heal (proactive): hourly w32tm /resync so the endpoint's
    # clock can't drift past the 5-min HMAC window without us noticing. Cheap
    # on a working NTP path (~50ms) and silent no-op the other 59 polls/hour.
    # See LOUD comment block above _TimeSyncForce + deploy_endpoint.ps1 Step 6.
    _TimeSyncIfStale

    # OTA self-update: fetch the manifest, compare version, fetch + apply
    # the new handler if the server's live version differs from ours. Runs
    # BEFORE everything else so a fresh-from-update agent will execute
    # the new code path on the NEXT tick (current tick keeps running the
    # old in-memory copy -- PowerShell loaded it at task launch).
    _HandlerSelfUpdate

    # Self-heal: ensure isolation is still in place if the registry says
    # this host should be isolated. AV / GPO / manual `netsh` can clobber
    # our rules; we restore within one poll interval.
    _IsolationSelfHeal

    Write-Log "INFO" "Polling $ServerUrl/agents/$AgentId/poll"

    $resp = Invoke-RestMethod -Method Post `
        -Uri "$ServerUrl/agents/$AgentId/poll" `
        -Headers @{ "Authorization" = (Get-AuthHeader); "Content-Type" = "application/json" } `
        -Body "{}" -TimeoutSec 30 -UseBasicParsing

    if (-not $resp.commands -or $resp.commands.Count -eq 0) {
        Write-Log "INFO" "No pending commands"
        # Even with no commands, heartbeat so the dashboard sees the right
        # status (isolated / panic-recovered). The poll itself already
        # set last_status=ok; this overwrites it with our local truth.
        Send-Heartbeat (Get-HeartbeatStatus)
        exit 0
    }

    foreach ($env in $resp.commands) {
        # 1. Verify signature over the inner payload bytes
        $expectedSig = Get-HmacHex -Key $secretBytes -Message $env.signed_payload
        if ($expectedSig -ne $env.signature) {
            Write-Log "SECURITY" "Signature mismatch - DROPPING command (possible tamper)"
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
            Write-Log "SECURITY" "Command targeted $($cmd.agent_id) but we are $AgentId - DROPPING"
            continue
        }

        # 4. Verify expiry
        try {
            $expUtc = [DateTime]::Parse($cmd.expires_at).ToUniversalTime()
            if ($expUtc -lt [DateTime]::UtcNow) {
                Write-Log "WARN" "Command $($cmd.command_id) ($($cmd.command_type)) expired - skipping"
                Send-Result $cmd.command_id @{ status = "rejected"; output = "Command expired before execution" }
                continue
            }
        } catch {
            Write-Log "ERROR" "Bad expires_at on $($cmd.command_id): $_"
            continue
        }

        Write-Log "INFO" "Executing $($cmd.command_type) [$($cmd.command_id)]"

        # 5. Dispatch via whitelist. Handlers receive the params dict + the
        #    full command envelope as a 2nd positional arg. Existing handlers
        #    that only declare param($Params) silently drop the 2nd arg --
        #    backward-compatible. Isolation handlers read $Cmd.command_id +
        #    issued_by for state persistence + audit.
        $handler = $Handlers["$($cmd.command_type)"]
        if (-not $handler) {
            $result = @{ status = "rejected"; output = "Unknown command type: $($cmd.command_type)" }
        } else {
            try {
                # Explicit if/else (PS 5.1 try-block parser hardening).
                $params = @{}
                if ($cmd.params) { $params = $cmd.params }
                $result = & $handler $params $cmd
            } catch {
                $result = @{ status = "failure"; output = "Handler exception: $_" }
            }
        }

        Write-Log "INFO" ("Result: {0} - {1}" -f $result.status,
            "$($result.output)".Substring(0, [Math]::Min(160, "$($result.output)".Length)))

        # 6. Report back
        Send-Result $cmd.command_id $result
    }

    # Heartbeat after all commands processed so the dashboard reflects
    # post-execution state (e.g. isolated:standard after an isolate result
    # was posted; ok after unisolate).
    Send-Heartbeat (Get-HeartbeatStatus)
} catch {
    $err = "$_"
    Write-Log "ERROR" "Poll iteration failed: $err"

    # Clock-skew self-heal (reactive): if the failure was an HTTP 401 the most
    # likely cause is the endpoint's clock having drifted outside the server's
    # 5-min HMAC window. Force a w32tm /resync; the NEXT scheduled-task tick
    # (60s away) will retry the poll with a corrected clock. The debounce
    # inside _TimeSyncForce prevents this from spamming on a permanently-
    # unreachable NTP source. See LOUD comment in deploy_endpoint.ps1 Step 6.
    if ($err -match "(?i)(401|Unauthorized|Authentication failed)") {
        Write-Log "WARN" "Auth failed - attempting clock-skew self-heal"
        $null = _TimeSyncForce -Reason "post-401"
    }

    # Best-effort heartbeat even on error -- useful so the dashboard sees the
    # isolated state even if the command path crashed.
    try { Send-Heartbeat (Get-HeartbeatStatus) } catch { }
    exit 1
}
