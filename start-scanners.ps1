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
$clamExe    = 'C:\Program Files\ClamAV\clamd.exe'
$freshExe   = 'C:\Program Files\ClamAV\freshclam.exe'
$dbDir      = Join-Path $projRoot 'clamav-db'
$cfgDir     = Join-Path $projRoot 'config'
$clamConf   = Join-Path $cfgDir 'clamd.conf'
$freshConf  = Join-Path $cfgDir 'freshclam.conf'

if (-not (Test-Path $clamExe)) {
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

# Bootstrap signature database if it is missing.
if (-not (Test-Path "$dbDir\main.cvd")) {
  Write-Host "No ClamAV signature DB at $dbDir - attempting initial update."
  & $freshExe --config-file="$freshConf"
  if (-not (Test-Path "$dbDir\main.cvd")) {
    Write-Host "Signature download failed. Check network, then run:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\start-scanners.ps1`" -Update"
    exit 0
  }
}

# Manual signature update requested.
if ($Update) {
  Write-Host 'Updating ClamAV signatures...'
  & $freshExe --config-file="$freshConf"
  exit $LASTEXITCODE
}

# Already listening?
$listening = Get-NetTCPConnection -LocalPort 3310 -State Listen | Select-Object -First 1
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
    $listening = Get-NetTCPConnection -LocalPort 3310 -State Listen | Select-Object -First 1
    if ($listening) { break }
  }
  if ($listening) { Write-Host "ClamAV started on 127.0.0.1:3310 (pid $($listening.OwningProcess))." }
  else { Write-Host "Could not start ClamAV after 90 s - check $clamConf and $dbDir\clamd.log" }
} catch {
  Write-Host "Error starting ClamAV: $($_.Exception.Message)"
}