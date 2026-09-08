$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $taskRoot
$appSrc = Join-Path $projectRoot 'server\src\main\java\com\sentinelmail\App.java'
$testSrc = Join-Path $taskRoot 'com\sentinelmail\ServerTests.java'
$classes = Join-Path $taskRoot 'classes'
New-Item -ItemType Directory -Force -Path $classes | Out-Null
Write-Host "Compiling App + tests..." -ForegroundColor Cyan
javac --add-modules jdk.httpserver -d $classes $appSrc $testSrc
if (-not $?) { Write-Host "Compilation failed." -ForegroundColor Red; exit 1 }
Write-Host "Running unit tests..." -ForegroundColor Cyan
java --add-modules jdk.httpserver -cp $classes com.sentinelmail.ServerTests
exit $LASTEXITCODE
