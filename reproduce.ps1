[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$PythonExecutable
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$Driver = Join-Path $Repo 'scripts\reproduce_frozen.py'

if (-not (Test-Path -LiteralPath $Driver -PathType Leaf)) {
    throw 'TraceSOC reproduction driver is missing.'
}

$PrefixArguments = @()

if (-not [string]::IsNullOrWhiteSpace($PythonExecutable)) {
    if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
        throw 'Specified Python executable does not exist.'
    }

    $Python = $PythonExecutable
}
else {
    $RepoPython = Join-Path $Repo '.venv\Scripts\python.exe'

    if (Test-Path -LiteralPath $RepoPython -PathType Leaf) {
        $Python = $RepoPython
    }
    else {
        $PyLauncher = Get-Command py -ErrorAction SilentlyContinue

        if ($null -ne $PyLauncher) {
            $Python = $PyLauncher.Source
            $PrefixArguments = @('-3')
        }
        else {
            $PythonCommand = Get-Command python -ErrorAction SilentlyContinue

            if ($null -eq $PythonCommand) {
                throw 'Python 3.11+ could not be located.'
            }

            $Python = $PythonCommand.Source
        }
    }
}

Write-Host ('=' * 78)
Write-Host 'TraceSOC v0.4 clean reproduction'
Write-Host "Repository      : $Repo"
Write-Host "Evidence        : $EvidenceDirectory"
Write-Host "Output          : $OutputDirectory"
Write-Host "Python launcher : $Python"
Write-Host ('=' * 78)

& $Python @PrefixArguments -B $Driver `
    --repo $Repo `
    --evidence $EvidenceDirectory `
    --output $OutputDirectory

$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    throw "TraceSOC reproduction failed with exit code $ExitCode."
}

Write-Host ''
Write-Host 'TRACESOC_ONE_COMMAND_REPRODUCTION=PASS'