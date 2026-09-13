$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $taskRoot 'server\src\main\java\com\sentinelmail\App.java'
$classes = Join-Path $taskRoot 'server\target\classes'
# Bring up optional scanner backends (ClamAV daemon) so LIVE scans are available out of the box.
& (Join-Path $taskRoot 'start-scanners.ps1')
# Bring up the outbound-alert receiver (local alert inbox) detached so this
# script never blocks on the inbox loop. It exits fast if already listening.
$inboxScript = Join-Path $taskRoot 'start-alert-inbox.ps1'
$l = Get-NetTCPConnection -LocalPort 9290 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($l) { Write-Host "Alert inbox already listening on 127.0.0.1:9290 (pid $($l.OwningProcess))." }
else {
  Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$inboxScript`"" -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds 1
}
Write-Host "Compiling Cipher Squad engine..."
New-Item -ItemType Directory -Force -Path $classes | Out-Null
javac --add-modules jdk.httpserver -encoding UTF-8 -d $classes $source
if (-not $?) { Write-Host "Compilation failed."; exit 1 }
Write-Host "Starting Cipher Squad at http://127.0.0.1:8080 . Press Ctrl+C to stop."
java --add-modules jdk.httpserver -cp $classes com.sentinelmail.App
