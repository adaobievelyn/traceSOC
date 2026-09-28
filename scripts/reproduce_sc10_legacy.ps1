param(
    [string]$PythonExe = 'python',
    [string]$Commit = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path

$Clean = Join-Path $Repo 'clean.ps1'
$Provision = Join-Path $Repo 'provision.ps1'
$Build = Join-Path $Repo 'build.ps1'
$Test = Join-Path $Repo 'test.ps1'

Set-Location -LiteralPath $Repo

$Resolved = Get-Command $PythonExe -ErrorAction Stop

$BasePython = $Resolved.Source

if ([string]::IsNullOrWhiteSpace($BasePython)) {
    $BasePython = $Resolved.Path
}

if ([string]::IsNullOrWhiteSpace($BasePython)) {
    throw "STOP: unable to resolve base Python executable."
}

$RepoVenv = (
    Join-Path $Repo '.venv'
).TrimEnd('\')

$ResolvedBase = (
    [System.IO.Path]::GetFullPath($BasePython)
)

if ($ResolvedBase.StartsWith(
    $RepoVenv + '\',
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "STOP: base Python resolves inside repository .venv. Deactivate it or pass a system Python 3.13.14 executable."
}

$GitCommand = Get-Command git -ErrorAction SilentlyContinue
$GitMetadataPath = Join-Path $Repo '.git'
$ResolvedHead = ''

if (
    $null -ne $GitCommand -and
    (Test-Path -LiteralPath $GitMetadataPath)
) {
    $GitHeadOutput = @(
        & git -C $Repo rev-parse HEAD
    )

    if ($LASTEXITCODE -ne 0) {
        throw "STOP: Git metadata exists but repository HEAD could not be resolved."
    }

    $ResolvedHead = (
        $GitHeadOutput -join "`n"
    ).Trim()
}

if (-not [string]::IsNullOrWhiteSpace($ResolvedHead)) {
    if ([string]::IsNullOrWhiteSpace($Commit)) {
        $Commit = $ResolvedHead
    }
    elseif (
        $Commit.ToLowerInvariant() -ne
        $ResolvedHead.ToLowerInvariant()
    ) {
        throw "STOP: supplied commit $Commit does not match repository HEAD $ResolvedHead."
    }
}
elseif ([string]::IsNullOrWhiteSpace($Commit)) {
    throw "STOP: Git metadata is unavailable; pass the frozen 40-character commit explicitly."
}

if ($Commit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "STOP: commit must be a 40-character hexadecimal Git object ID."
}

$Commit = $Commit.ToLowerInvariant()

function Stop-RepositoryVenvProcesses {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RepositoryRoot
    )

    $VenvRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $RepositoryRoot '.venv')
    ).TrimEnd('\')

    $Prefix = $VenvRoot + '\'
    $Stopped = 0

    $Processes = @(
        Get-CimInstance `
            Win32_Process `
            -ErrorAction SilentlyContinue
    )

    foreach ($Process in $Processes) {
        $Executable = [string]$Process.ExecutablePath

        if ([string]::IsNullOrWhiteSpace($Executable)) {
            continue
        }

        $ExecutableFull = $Executable

        try {
            $ExecutableFull = [System.IO.Path]::GetFullPath(
                $Executable
            )
        }
        catch {
            continue
        }

        if (
            -not $ExecutableFull.StartsWith(
                $Prefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }

        Write-Host (
            "REPRODUCE_VENV_LOCK_PROCESS=" +
            $Process.ProcessId +
            "|" +
            $ExecutableFull
        )

        Stop-Process `
            -Id ([int]$Process.ProcessId) `
            -Force `
            -ErrorAction SilentlyContinue

        $Stopped++
    }

    if ($Stopped -gt 0) {
        Start-Sleep -Milliseconds 1000
    }

    Write-Host "REPRODUCE_VENV_PROCESSES_STOPPED=$Stopped"
}


function Invoke-LockSafeClean {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CleanScript,

        [Parameter(Mandatory=$true)]
        [string]$RepositoryRoot
    )

    $LastFailure = $null

    for ($Attempt = 1; $Attempt -le 6; $Attempt++) {
        Write-Host "REPRODUCE_CLEAN_ATTEMPT=$Attempt"

        try {
            & $CleanScript

            Write-Host "REPRODUCE_CLEAN=PASS"
            return
        }
        catch {
            $LastFailure = $_

            $Text = (
                $_ |
                Out-String
            )

            Write-Host (
                "REPRODUCE_CLEAN_RETRY_REASON=" +
                $_.Exception.Message
            )

            $LooksLikeVenvLock = (
                $Text -match '\.venv' -or
                $Text -match 'python\.exe' -or
                $Text -match 'Access to the path' -or
                $Text -match 'being used by another process'
            )

            if (-not $LooksLikeVenvLock) {
                throw
            }

            Stop-RepositoryVenvProcesses `
                -RepositoryRoot $RepositoryRoot

            Start-Sleep `
                -Milliseconds (500 * $Attempt)
        }
    }

    if ($null -ne $LastFailure) {
        throw (
            "STOP: clean.ps1 still fails after lock-safe retries: " +
            $LastFailure.Exception.Message
        )
    }

    throw "STOP: clean.ps1 failed without a captured error."
}


Invoke-LockSafeClean `
    -CleanScript $Clean `
    -RepositoryRoot $Repo

& $Provision -PythonExe $BasePython

& $Build

$RepoPython = Join-Path $Repo '.venv\Scripts\python.exe'
$Sc10Root = Join-Path $Repo 'results\sc10'
$Sc10Analytic = Join-Path $Sc10Root 'analytic'
$Sc10Regenerated = Join-Path $Sc10Root 'regenerated-root'
$Sc10Ledger = Join-Path $Sc10Root 'sc10-reproduction.json'
$Sc10Helper = Join-Path $Repo 'scripts\run_sc10_analytic_path.py'
$RootIndexScript = Join-Path $Repo 'scripts\rebuild_root_indexes.py'

if (-not (Test-Path -LiteralPath $RepoPython -PathType Leaf)) {
    throw "STOP: repository Python missing after build."
}

if (-not (Test-Path -LiteralPath $Sc10Helper -PathType Leaf)) {
    throw "STOP: SC10 analytic helper missing."
}

if (-not (Test-Path -LiteralPath $RootIndexScript -PathType Leaf)) {
    throw "STOP: root-index regeneration script missing."
}

if (Test-Path -LiteralPath $Sc10Root) {
    Remove-Item `
        -LiteralPath $Sc10Root `
        -Recurse `
        -Force
}

New-Item `
    -ItemType Directory `
    -Path $Sc10Root `
    -Force | Out-Null

Write-Host "SC10_STAGE=INSTALL|PASS"

& $RepoPython `
    $Sc10Helper `
    --repo $Repo `
    --output-dir $Sc10Analytic

if ($LASTEXITCODE -ne 0) {
    throw "STOP: SC10 ingest/detect/correlate/explain path failed."
}

Write-Host "SC10_STAGE=INGEST|PASS"
Write-Host "SC10_STAGE=DETECT|PASS"
Write-Host "SC10_STAGE=CORRELATE|PASS"
Write-Host "SC10_STAGE=EXPLAIN|PASS"

& $Test -Commit $Commit

Write-Host "SC10_STAGE=TEST|PASS"

if (Test-Path -LiteralPath $Sc10Regenerated) {
    Remove-Item `
        -LiteralPath $Sc10Regenerated `
        -Recurse `
        -Force
}

& $RepoPython `
    $RootIndexScript `
    --repo $Repo `
    --output-dir $Sc10Regenerated

if ($LASTEXITCODE -ne 0) {
    throw "STOP: SC10 root-index regeneration failed."
}

$RegeneratedNames = @(
    'evidence-index.csv',
    'ioc-set.csv',
    'timeline.csv'
)

$RegeneratedHashes = [ordered]@{}

foreach ($Name in $RegeneratedNames) {
    $Canonical = Join-Path $Repo $Name
    $Regenerated = Join-Path $Sc10Regenerated $Name

    if (-not (Test-Path -LiteralPath $Canonical -PathType Leaf)) {
        throw "STOP: canonical root artifact missing: $Name"
    }

    if (-not (Test-Path -LiteralPath $Regenerated -PathType Leaf)) {
        throw "STOP: regenerated root artifact missing: $Name"
    }

    $CanonicalSha = (
        Get-FileHash `
            -LiteralPath $Canonical `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $RegeneratedSha = (
        Get-FileHash `
            -LiteralPath $Regenerated `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    Write-Host (
        "SC10_REGENERATED_ROOT=" +
        $Name +
        "|" +
        $RegeneratedSha
    )

    if ($CanonicalSha -ne $RegeneratedSha) {
        throw (
            "STOP: regenerated root artifact differs from repository root: " +
            $Name
        )
    }

    $RegeneratedHashes[$Name] = $RegeneratedSha
}

Write-Host "SC10_STAGE=REGENERATE|PASS"

$AcceptanceReport = Join-Path `
    $Repo `
    'results\acceptance\public-test-results.json'

if (-not (Test-Path -LiteralPath $AcceptanceReport -PathType Leaf)) {
    throw "STOP: authoritative public-test report missing."
}

$Acceptance = (
    Get-Content `
        -LiteralPath $AcceptanceReport `
        -Raw
) | ConvertFrom-Json

$AuthoritativeDiscovered = [int]$Acceptance.full_regression.discovered
$AuthoritativeTestsRun = [int]$Acceptance.full_regression.tests_run
$AuthoritativePassed = [int]$Acceptance.full_regression.passed

if (
    $Acceptance.result -ne 'PASS' -or
    $AuthoritativeDiscovered -le 0 -or
    $AuthoritativeTestsRun -ne $AuthoritativeDiscovered -or
    $AuthoritativePassed -ne $AuthoritativeDiscovered
) {
    throw "STOP: SC10 authoritative regression is not complete PASS."
}

foreach ($Field in @(
    'failed',
    'errors',
    'skipped',
    'expected_failures',
    'unexpected_successes'
)) {
    if ([int]$Acceptance.full_regression.$Field -ne 0) {
        throw "STOP: SC10 test result contains nonzero $Field."
    }
}

$AcceptanceClasses = @(
    $Acceptance.public_acceptance.PSObject.Properties
)

if ($AcceptanceClasses.Count -ne 4) {
    throw "STOP: SC10 public acceptance class count is not four."
}

foreach ($Property in $AcceptanceClasses) {
    if ($Property.Value.result -ne 'PASS') {
        throw (
            "STOP: SC10 public acceptance class failed: " +
            $Property.Name
        )
    }
}

$AnalyticRecord = Join-Path `
    $Sc10Analytic `
    'analytic-path.json'

$ScenarioRecord = Join-Path `
    $Sc10Analytic `
    'scenario-result.json'

$ExplanationRecord = Join-Path `
    $Sc10Analytic `
    'finding-explanation.json'

foreach ($Path in @(
    $AnalyticRecord,
    $ScenarioRecord,
    $ExplanationRecord
)) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "STOP: SC10 analytic artifact missing: $Path"
    }
}

$Ledger = [ordered]@{
    schema_version = 'tracesoc-sc10-reproduction-v1'
    commit = $Commit
    entry_point = 'reproduce.ps1'
    data_class = 'CONTROLLED_SYNTHETIC_SCENARIO'
    install = 'PASS'
    ingest = 'PASS'
    detect = 'PASS'
    correlate = 'PASS'
    explain = 'PASS'
    test = 'PASS'
    regenerate = 'PASS'
    authoritative_tests = ($AuthoritativePassed.ToString() + '/' + $AuthoritativeDiscovered.ToString())
    public_acceptance_classes = '4/4'
    analytic_path_sha256 = (
        Get-FileHash `
            -LiteralPath $AnalyticRecord `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    scenario_result_sha256 = (
        Get-FileHash `
            -LiteralPath $ScenarioRecord `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    finding_explanation_sha256 = (
        Get-FileHash `
            -LiteralPath $ExplanationRecord `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    public_test_report_sha256 = (
        Get-FileHash `
            -LiteralPath $AcceptanceReport `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    regenerated_root_indexes = $RegeneratedHashes
    regenerated_matches_repository_root = $true
    root_indexes_mutated = $false
    stage9a_access = $false
    holdout_access = $false
    real_incident_claim = $false
}

$LedgerJson = (
    $Ledger |
    ConvertTo-Json -Depth 8
) + "`n"

[System.IO.File]::WriteAllText(
    $Sc10Ledger,
    $LedgerJson,
    (New-Object System.Text.UTF8Encoding($false))
)

$Sc10LedgerSha = (
    Get-FileHash `
        -LiteralPath $Sc10Ledger `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Host "SC10_REPRODUCTION_LEDGER=results/sc10/sc10-reproduction.json"
Write-Host "SC10_REPRODUCTION_LEDGER_SHA256=$Sc10LedgerSha"
Write-Host "SC10_REQUIRED_CHAIN=PASS"

$Report = Join-Path $Repo 'results\acceptance\public-test-results.json'

if (-not (Test-Path -LiteralPath $Report -PathType Leaf)) {
    throw "STOP: final public test report missing."
}

$ReportSha = (
    Get-FileHash `
        -LiteralPath $Report `
        -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Host "REPRODUCE_RESULT=PASS"
Write-Host "SOURCE_COMMIT=$Commit"
Write-Host "PUBLIC_TEST_REPORT=results/acceptance/public-test-results.json"
Write-Host "PUBLIC_TEST_REPORT_SHA256=$ReportSha"
