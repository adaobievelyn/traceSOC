param(
    [string]$Commit = '',
    [string]$Output = 'results\acceptance\public-test-results.json'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Repo '.venv\Scripts\python.exe'
$Reporter = Join-Path $Repo 'scripts\run_public_acceptance.py'
$OutputPath = Join-Path $Repo $Output

Set-Location -LiteralPath $Repo

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "STOP: .venv Python missing. Run provision.ps1 and build.ps1 first."
}

if (-not (Test-Path -LiteralPath $Reporter -PathType Leaf)) {
    throw "STOP: public acceptance reporter missing."
}

if ([string]::IsNullOrWhiteSpace($Commit)) {
    $Commit = (git rev-parse HEAD).Trim()

    if ($LASTEXITCODE -ne 0) {
        throw "STOP: could not resolve Git commit."
    }
}

$PreviousPythonPath = $env:PYTHONPATH

try {
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

    & $Python $Reporter `
        --repo $Repo `
        --commit $Commit `
        --output $OutputPath

    if ($LASTEXITCODE -ne 0) {
        throw "STOP: public acceptance suite failed."
    }
}
finally {
    if ($null -ne $PreviousPythonPath) {
        $env:PYTHONPATH = $PreviousPythonPath
    }
}

if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "STOP: machine-readable public test report missing."
}

$Report = (
    Get-Content `
        -LiteralPath $OutputPath `
        -Raw
) | ConvertFrom-Json

if ($Report.result -ne 'PASS') {
    throw "STOP: machine-readable report is not PASS."
}

$Discovered = [int]$Report.full_regression.discovered
$TestsRun = [int]$Report.full_regression.tests_run
$Passed = [int]$Report.full_regression.passed

if ($Discovered -le 0) {
    throw "STOP: public regression discovered zero tests."
}

if ($TestsRun -ne $Discovered) {
    throw "STOP: public regression did not run every discovered test."
}

if ($Passed -ne $Discovered) {
    throw "STOP: not every discovered public regression test passed."
}

foreach ($Field in @(
    'failed',
    'errors',
    'skipped',
    'expected_failures',
    'unexpected_successes'
)) {
    if ([int]$Report.full_regression.$Field -ne 0) {
        throw "STOP: public regression contains nonzero $Field."
    }
}

$PublicClasses = @(
    $Report.public_acceptance.PSObject.Properties
)

if ($PublicClasses.Count -ne 4) {
    throw "STOP: report does not contain four public acceptance classes."
}

foreach ($Property in $PublicClasses) {
    if ($Property.Value.result -ne 'PASS') {
        throw "STOP: public acceptance class failed: $($Property.Name)"
    }
}

$ReportSha = (
    Get-FileHash `
        -LiteralPath $OutputPath `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Host "TEST_RESULT=PASS"
Write-Host ("FULL_REGRESSION={0}/{1}_PASS" -f $Passed, $Discovered)
Write-Host "PUBLIC_ACCEPTANCE_CLASSES=4/4_PASS"
Write-Host "PUBLIC_TEST_REPORT=$Output"
Write-Host "PUBLIC_TEST_REPORT_SHA256=$ReportSha"
