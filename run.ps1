$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $taskRoot 'server\src\main\java\com\sentinelmail\App.java'
$classes = Join-Path $taskRoot 'server\target\classes'
# Bring up optional scanner backends (ClamAV daemon) so LIVE scans are available out of the box.
& (Join-Path $taskRoot 'start-scanners.ps1')
# Bring up the outbound-alert receiver (local alert inbox) if not already listening.
& (Join-Path $taskRoot 'start-alert-inbox.ps1')
Write-Host "Compiling Cipher Squad engine..."
New-Item -ItemType Directory -Force -Path $classes | Out-Null
javac --add-modules jdk.httpserver -encoding UTF-8 -d $classes $source
if (-not $?) { Write-Host "Compilation failed."; exit 1 }
Write-Host "Starting Cipher Squad at http://127.0.0.1:8080 . Press Ctrl+C to stop."
java --add-modules jdk.httpserver -cp $classes com.sentinelmail.App
