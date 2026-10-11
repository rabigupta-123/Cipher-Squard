<#
.SYNOPSIS
    Compiles the offline email-attribution toolkit and runs the full test matrix.

.DESCRIPTION
    Builds every source file plus every test driver into build/ with the JDK on PATH, then runs:

      1. The four module self-tests (EmailParser, Enrich, Attribution, Correlate).
      2. The frozen Phase 1 suite (regression).
      3. The Phase 2 suite.
      4. The Phase 3 suite (the loopback HTTP API, auth, cases, audit and STIX export).

    Exits non-zero if any stage fails, so it can gate a commit or a release.

.EXAMPLE
    .\run-tests.ps1
    .\run-tests.ps1 -Quiet
#>
[CmdletBinding()]
param(
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# javac and java write diagnostics to stderr, and PowerShell surfaces any native-command stderr
# as an error record. Under 'Stop' a javac *note* about unchecked operations would abort the run
# before javac's own exit code was ever consulted. Success is therefore decided by $LASTEXITCODE
# alone, which is the authoritative signal, and stderr is captured as text.
$ErrorActionPreference = 'Continue'

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
Set-Location $root

if (-not (Get-Command javac -ErrorAction SilentlyContinue)) {
    Write-Error "javac not found on PATH. Install a JDK 25 or newer, or set JAVA_HOME."
    exit 1
}

$sources = @(
    Get-ChildItem -Path (Join-Path $root 'src') -Filter *.java -Recurse |
        ForEach-Object { $_.FullName }
) + @(
    (Join-Path $root (Join-Path 'tests' 'Phase1Regression.java')),
    (Join-Path $root (Join-Path 'tests' 'Regression.java')),
    (Join-Path $root (Join-Path 'tests' 'phase2.java')),
    (Join-Path $root (Join-Path 'tests' 'phase3.java')),
    (Join-Path $root (Join-Path 'tests' 'EndToEndWorkflow.java'))
)

$outDir = Join-Path $root 'build'
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

# Delete previously compiled classes before compiling. javac only rewrites what it needs, so a
# suite that is dropped from $sources, renamed, or that stops compiling stays behind as a stale
# .class and is still executed by the run below. That is worse than a missing stage: the report
# shows a passing suite whose source no longer backs it. Only *.class is removed, so build\test-state
# and any other build output is left alone.
Get-ChildItem -Path $outDir -Filter *.class -Recurse -File -ErrorAction SilentlyContinue |
    Remove-Item -Force

# The suites create users, cases and audit records, so they are pointed at a throwaway state
# directory. Without this a test run appends to data\cases.ndjson and data\audit.ndjson, leaving
# credentials, cases and a non-empty audit chain behind -- which both pollutes the shipped store
# and makes the next run start from a different state than this one did.
$testData = Join-Path $outDir 'test-state'
if (Test-Path -LiteralPath $testData) {
    Remove-Item -LiteralPath $testData -Recurse -Force
}
New-Item -ItemType Directory -Path $testData | Out-Null

$failures = @()

function Write-Stage {
    param([string] $Name, [string] $Status)
    if (-not $Quiet) {
        $colour = if ($Status -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host ("{0,-14} {1}" -f $Name, $Status) -ForegroundColor $colour
    }
}

# --- compile -----------------------------------------------------------------

if (-not $Quiet) { Write-Host "`n==> compiling" -ForegroundColor Cyan }

$javaVer = ((& javac -version 2>&1) -join ' ') -replace '.*javac\s+', '' -replace '\..*', ''
$releaseArgs = if ($javaVer -match '^\d+$' -and [int]$javaVer -ge 21) { @("--release", "$javaVer") } else { @("--release", "21") }

$compileLog = & javac @releaseArgs -encoding UTF-8 -d $outDir $sources 2>&1
if ($LASTEXITCODE -ne 0) {
    $compileLog | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Stage 'compile' 'FAIL'
    exit 1
}
Write-Stage 'compile' 'PASS'

# --- run ---------------------------------------------------------------------

$stages = @(
    @{ Name = 'EmailParser';        Class = 'EmailParser' },
    @{ Name = 'Enrich';             Class = 'Enrich' },
    @{ Name = 'Attribution';        Class = 'Attribution' },
    @{ Name = 'Correlate';          Class = 'Correlate' },
    @{ Name = 'Phase1Regression';   Class = 'Phase1Regression' },
    @{ Name = 'Regression';         Class = 'Regression' },
    @{ Name = 'phase2';             Class = 'phase2' },
    @{ Name = 'phase3';             Class = 'phase3' },
    @{ Name = 'EndToEndWorkflow';   Class = 'EndToEndWorkflow' }
)

if (-not $Quiet) { Write-Host "`n==> running" -ForegroundColor Cyan }

foreach ($stage in $stages) {
    $output = & java "-Dcipher.squad.dataDir=$testData" -cp $outDir $stage.Class 2>&1
    $ok = ($LASTEXITCODE -eq 0) -and (($output | Select-String -Pattern '^RESULT: FAIL') -eq $null)

    if ($ok) {
        Write-Stage $stage.Name 'PASS'
        if (-not $Quiet) {
            $summary = $output | Select-String -Pattern '^(passed=|OK )' |
                Select-Object -Last 1 | ForEach-Object { $_.Line }
            if ($summary) { Write-Host "               $summary" -ForegroundColor DarkGray }
        }
    } else {
        Write-Stage $stage.Name 'FAIL'
        $failures += $stage.Name
        $output | Select-Object -Last 40 | ForEach-Object {
            Write-Host "               $_" -ForegroundColor Red
        }
    }
}

# --- summary -----------------------------------------------------------------

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "ALL STAGES PASSED ($($stages.Count) stages)" -ForegroundColor Green
    Remove-Item -LiteralPath $testData -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}

Write-Host "FAILED: $($failures -join ', ')" -ForegroundColor Red
Write-Host "Test state kept for inspection: $testData" -ForegroundColor DarkGray
exit 1
