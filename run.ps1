<#
.SYNOPSIS
    Cipher Squad - Platform Launcher (Pure Java JDK 25 Local-First SOC Engine)

.DESCRIPTION
    Compiles the project (if needed), verifies/bootstraps local runtime data stores,
    provisions the root audit signing key and administrative credentials if not already
    configured, and launches the built-in HTTP server on http://127.0.0.1:8080.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Port 9090
#>
[CmdletBinding()]
param(
    [int] $Port = 8080,
    [switch] $SkipBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
Set-Location $root

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " CIPHER SQUAD - AI-Powered Email Threat Detection Platform" -ForegroundColor Cyan
Write-Host " Architecture: Pure Java JDK 25 Local-First SOC Engine" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify JDK
if (-not (Get-Command javac -ErrorAction SilentlyContinue)) {
    Write-Error "javac not found on PATH. Please install Java JDK 25 or newer, or set JAVA_HOME."
    exit 1
}

# 2. Build directories
$outDir = Join-Path $root 'build'
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$dataDir = Join-Path $root 'data'
if (-not (Test-Path -LiteralPath $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
}

# 3. Compile sources
Write-Host "==> Compiling source files..." -ForegroundColor Yellow
$sources = Get-ChildItem -Path (Join-Path $root 'src') -Filter *.java -Recurse | ForEach-Object { $_.FullName }
& javac --release 25 -encoding UTF-8 -d $outDir $sources
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed. Aborting startup."
    exit 1
}
Write-Host "    Compilation successful." -ForegroundColor Green

# 4. Bootstrap Provisioning (Keys & Admin user if missing)
Write-Host "==> Initializing local runtime stores & keys..." -ForegroundColor Yellow
$keyPath = Join-Path $dataDir "keys\ed25519.pem"
if (-not (Test-Path -LiteralPath $keyPath)) {
    Write-Host "    Generating root Ed25519 audit signing key..." -ForegroundColor DarkGray
    & java -cp $outDir App --init-key
}

# Check if admin user exists in data/users.ndjson
$usersPath = Join-Path $dataDir "users.ndjson"
$needsUser = $true
if (Test-Path -LiteralPath $usersPath) {
    $lines = Get-Content -LiteralPath $usersPath -ErrorAction SilentlyContinue
    if ($lines -and $lines.Count -gt 0) {
        $needsUser = $false
    }
}

if ($needsUser) {
    $bootstrapPw = $env:CIPHER_BOOTSTRAP_PASSWORD
    if (-not $bootstrapPw -or $bootstrapPw.Length -lt 12) {
        $bytes = New-Object byte[] 15
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $bootstrapPw = [Convert]::ToBase64String($bytes).Replace('+', 'X').Replace('/', 'Y') + "!9aZ"
    }

    $tmp = New-TemporaryFile
    try {
        Set-Content -Path $tmp -Value "$bootstrapPw`r`n$bootstrapPw`r`n" -Encoding ascii
        $process = Start-Process -FilePath "java" -ArgumentList "-cp", $outDir, "App", "--init-user", "admin" `
            -RedirectStandardInput $tmp -NoNewWindow -Wait -PassThru
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "[SECURITY ALERT] INITIAL ADMINISTRATOR BOOTSTRAP ACCOUNT GENERATED" -ForegroundColor Yellow
    Write-Host "  Account  : admin" -ForegroundColor Cyan
    Write-Host "  Password : $bootstrapPw" -ForegroundColor White
    Write-Host "  Notice   : Single-use bootstrap credential. Record immediately." -ForegroundColor Yellow
    Write-Host "             Never commit or persist passwords to shared logs." -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

Write-Host "    Runtime configuration verified." -ForegroundColor Green
Write-Host ""
Write-Host "==> Starting HTTP Service on http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "    Press Ctrl+C to terminate the server." -ForegroundColor DarkGray
Write-Host ""

if (-not $SkipBrowser) {
    Start-Process "http://127.0.0.1:$Port" -ErrorAction SilentlyContinue
}

& java -cp $outDir App $Port
