[CmdletBinding()]
param(
    [string]$PythonExe = 'python'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $Repo

$TechnicalCommit =
    '8751a679f36b4983cdd3d2b0b35f44e9a11c4f39'

Write-Host ('=' * 78)
Write-Host 'TraceSOC finalist clean build and acceptance reproduction'
Write-Host "Repository          : $Repo"
Write-Host "Technical candidate : $TechnicalCommit"
Write-Host ('=' * 78)

& git merge-base --is-ancestor $TechnicalCommit HEAD

if ($LASTEXITCODE -ne 0) {
    throw 'STOP: frozen technical candidate is not an ancestor of current HEAD.'
}

$CommittedProductDiff = @(
    git diff `
        --name-only `
        "$TechnicalCommit..HEAD" `
        -- src tests
)

if ($CommittedProductDiff.Count -ne 0) {
    $CommittedProductDiff | ForEach-Object {
        Write-Host "COMMITTED_PRODUCT_DRIFT=$_"
    }

    throw 'STOP: committed src/tests differ from frozen technical candidate.'
}

$WorkingProductDiff = @(
    git status `
        --porcelain=v1 `
        --untracked-files=all `
        -- src tests
)

if ($WorkingProductDiff.Count -ne 0) {
    $WorkingProductDiff | ForEach-Object {
        Write-Host "WORKTREE_PRODUCT_DRIFT=$_"
    }

    throw 'STOP: working src/tests differ from frozen technical candidate.'
}

$Clean = Join-Path $Repo 'clean.ps1'
$Provision = Join-Path $Repo 'provision.ps1'
$Build = Join-Path $Repo 'build.ps1'
$Test = Join-Path $Repo 'test.ps1'
$Report = Join-Path $Repo 'results\acceptance\public-test-results.json'

foreach ($Required in @(
    $Clean,
    $Provision,
    $Build,
    $Test
)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "STOP: required reproduction script missing: $Required"
    }
}

Write-Host ''
Write-Host '=== 1. CLEAN ==='
& $Clean

Write-Host ''
Write-Host '=== 2. PROVISION ==='
& $Provision -PythonExe $PythonExe

Write-Host ''
Write-Host '=== 3. BUILD ==='
& $Build

Write-Host ''
Write-Host '=== 4. TEST ==='
& $Test `
    -Commit $TechnicalCommit `
    -Output 'results\acceptance\public-test-results.json'

if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw 'STOP: final public acceptance report was not produced.'
}

$Result = (
    Get-Content -LiteralPath $Report -Raw
) | ConvertFrom-Json

if ($Result.result -ne 'PASS') {
    throw 'STOP: final public acceptance report is not PASS.'
}

$Discovered = [int]$Result.full_regression.discovered
$Run = [int]$Result.full_regression.tests_run
$Passed = [int]$Result.full_regression.passed

if (
    $Discovered -ne 524 -or
    $Run -ne 524 -or
    $Passed -ne 524
) {
    throw (
        "STOP: expected 524/524 finalist regression; " +
        "observed discovered=$Discovered run=$Run passed=$Passed"
    )
}

$Classes = @(
    $Result.public_acceptance.PSObject.Properties
)

if ($Classes.Count -ne 4) {
    throw 'STOP: expected four public acceptance classes.'
}

foreach ($Class in $Classes) {
    if ($Class.Value.result -ne 'PASS') {
        throw (
            'STOP: public acceptance class failed: ' +
            $Class.Name
        )
    }
}

$ReportHash = (
    Get-FileHash `
        -LiteralPath $Report `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Host ''
Write-Host ('=' * 78)
Write-Host 'FINALIST ONE-COMMAND REPRODUCTION RESULT'
Write-Host ('=' * 78)
Write-Host 'FINALIST_ONE_COMMAND_REPRODUCTION=PASS'
Write-Host "TECHNICAL_CANDIDATE=$TechnicalCommit"
Write-Host 'FULL_REGRESSION=524/524_PASS'
Write-Host 'PUBLIC_ACCEPTANCE_CLASSES=4/4_PASS'
Write-Host "PUBLIC_TEST_REPORT_SHA256=$ReportHash"
Write-Host 'PRODUCT_SOURCE_CHANGED=FALSE'
Write-Host 'TEST_SOURCE_CHANGED=FALSE'
Write-Host 'RAW_HOLDOUT_ACCESSED=FALSE'