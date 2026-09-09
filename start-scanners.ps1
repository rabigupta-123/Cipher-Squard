param([switch]$Update)

$ErrorActionPreference = 'SilentlyContinue'

# Cipher Squad scanner backend launcher (self-contained).
# Brings up the ClamAV daemon (clamd) on 127.0.0.1:3310 so the platform's
# ClamAV integration reports LIVE instead of UNAVAILABLE.
#
# Everything the scanners need lives inside this repository:
#   clamav-db\   - ClamAV signature database (main.cvd / daily.cvd / ...)
#   config\      - generated clamd.conf + freshclam.conf (paths derived from here)
#
# Install ClamAV once with:  winget install Cisco.ClamAV
# Update signatures with:    powershell -ExecutionPolicy Bypass -File .\start-scanners.ps1 -Update
# Yara is auto-detected by the server (yara64.exe on PATH or under ProgramFiles),
# and Rspamd has no Windows build, so no launcher is needed for those.

$projRoot   = $PSScriptRoot
$clamExe    = $null
foreach ($cand in @("$env:ProgramFiles\ClamAV\clamd.exe", "${env:ProgramFiles(x86)}\ClamAV\clamd.exe", 'C:\Program Files\ClamAV\clamd.exe')) {
  if (Test-Path -LiteralPath $cand) { $clamExe = $cand; break }
}
if (-not $clamExe) {
  Write-Host "ClamAV not found - install with: winget install Cisco.ClamAV"
  exit 0
}
$freshExe   = Join-Path (Split-Path $clamExe) 'freshclam.exe'
$dbDir      = Join-Path $projRoot 'clamav-db'
$cfgDir     = Join-Path $projRoot 'config'
$clamConf   = Join-Path $cfgDir 'clamd.conf'
$freshConf  = Join-Path $cfgDir 'freshclam.conf'

if (-not (Test-Path -LiteralPath $clamExe)) {
  Write-Host "ClamAV not found at $clamExe - install with: winget install Cisco.ClamAV"
  exit 0
}
New-Item -ItemType Directory -Force -Path $dbDir, $cfgDir | Out-Null

# Regenerate configs every run so they always match this checkout's location.
$dbQ = $dbDir -replace '"', '""'
@"
DatabaseDirectory "$dbQ"
LogFile "$dbQ\clamd.log"
LogTime yes
LogVerbose no
TCPSocket 3310
TCPAddr 127.0.0.1
LocalSocket "$dbQ\clamd.sock"
MaxThreads 2
"@ | Set-Content -LiteralPath $clamConf -Encoding ASCII

@"
DatabaseDirectory "$dbQ"
DatabaseMirror db.local.clamav.net
UpdateLogFile "$dbQ\freshclam.log"
LogTime yes
LogVerbose no
MaxAttempts 3
"@ | Set-Content -LiteralPath $freshConf -Encoding ASCII

# Run freshclam with a hard timeout so an unreachable mirror can never hang the launch.
function Invoke-FreshClam([string]$confPath, [string]$label) {
  if (-not (Test-Path -LiteralPath $confPath)) { Write-Host "$label : config missing: $confPath"; return 1 }
  $job = Start-Job -ScriptBlock { param($exe, $cfg) & $exe --config-file="$cfg" } -ArgumentList $freshExe, $confPath
  if (Wait-Job $job -Timeout 150) {
    Receive-Job $job
    $code = $job.State
    Remove-Job $job -Force
    Write-Host "$label : freshclam finished (state $code)."
    return 0
  }
  Stop-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -Force
  Write-Host "$label : freshclam timed out after 150 s while talking to the mirror."
  return 1
}

# Bootstrap signature database if it is missing.
if (-not (Test-Path "$dbDir\main.cvd")) {
  Write-Host "No ClamAV signature DB at $dbDir - attempting initial update."
  Invoke-FreshClam $freshConf 'init'
  if (-not (Test-Path "$dbDir\main.cvd")) {
    Write-Host "Signature download failed. Check network, then run:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\start-scanners.ps1`" -Update"
    exit 0
  }
}

# Manual signature update requested.
if ($Update) {
  Write-Host 'Updating ClamAV signatures...'
  Invoke-FreshClam $freshConf 'update'
  exit 0
}

# Already listening?
$listening = Get-NetTCPConnection -LocalPort 3310 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listening) {
  Write-Host "ClamAV already running on 127.0.0.1:3310 (pid $($listening.OwningProcess))."
  exit 0
}

# Start clamd (Invoke-CimMethod so it survives the launching shell).
try {
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CurrentDirectory = 'C:\Program Files\ClamAV'
    CommandLine = "`"$clamExe`" -c `"$clamConf`""
  } | Out-Null
  # Cold starts verify ~110 MB of signatures (3.6M of them) - poll up to 90 s.
  $listening = $null
  for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    $listening = Get-NetTCPConnection -LocalPort 3310 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listening) { break }
  }
  if ($listening) { Write-Host "ClamAV started on 127.0.0.1:3310 (pid $($listening.OwningProcess))." }
  else { Write-Host "Could not start ClamAV after 90 s - check $clamConf and $dbDir\clamd.log" }
} catch {
  Write-Host "Error starting ClamAV: $($_.Exception.Message)"
}
