$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location -LiteralPath $Repo

$ExactFiles = @(
    (Join-Path $Repo 'results\acceptance\public-test-results.json')
)

$GeneratedDirectories = @(
    (Join-Path $Repo '.venv'),
    (Join-Path $Repo 'build'),
    (Join-Path $Repo 'dist'),
    (Join-Path $Repo 'src\tracesoc.egg-info')
)

foreach ($Path in $ExactFiles) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Remove-Item -LiteralPath $Path -Force
    }
}

foreach ($Path in $GeneratedDirectories) {
    if (Test-Path -LiteralPath $Path) {
        Remove-Item `
            -LiteralPath $Path `
            -Recurse `
            -Force
    }
}

$PyCacheDirectories = @(
    Get-ChildItem `
        -LiteralPath $Repo `
        -Directory `
        -Filter '__pycache__' `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
)

foreach ($Path in $PyCacheDirectories) {
    if (Test-Path -LiteralPath $Path.FullName -PathType Container) {
        Remove-Item `
            -LiteralPath $Path.FullName `
            -Recurse `
            -Force
    }
}

$PycFiles = @(
    Get-ChildItem `
        -LiteralPath $Repo `
        -File `
        -Filter '*.pyc' `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue
)

foreach ($Path in $PycFiles) {
    if (Test-Path -LiteralPath $Path.FullName -PathType Leaf) {
        Remove-Item `
            -LiteralPath $Path.FullName `
            -Force
    }
}

$AcceptanceDirectory = Join-Path $Repo 'results\acceptance'

if (Test-Path -LiteralPath $AcceptanceDirectory -PathType Container) {
    $Remaining = @(
        Get-ChildItem `
            -LiteralPath $AcceptanceDirectory `
            -Force
    )

    if ($Remaining.Count -eq 0) {
        Remove-Item `
            -LiteralPath $AcceptanceDirectory `
            -Force
    }
}

Write-Host "CLEAN_RESULT=PASS"
Write-Host "RAW_EVIDENCE_TOUCHED=FALSE"
