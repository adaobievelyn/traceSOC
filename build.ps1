$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $Repo '.venv\Scripts\python.exe'
$Pyproject = Join-Path $Repo 'pyproject.toml'

$RequiredPython = '3.13.14'
$RequiredPip = '26.1.2'
$RequiredSetuptools = '84.0.0'
$RequiredTraceSoc = '0.1.0'

Set-Location -LiteralPath $Repo

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    throw "STOP: .venv missing. Run provision.ps1 first."
}

$PyprojectText = [System.IO.File]::ReadAllText($Pyproject)

if ($PyprojectText -notmatch 'setuptools==84\.0\.0') {
    throw "STOP: pyproject.toml does not contain the qualified exact setuptools pin."
}

$ObservedPython = (
    & $VenvPython -c "import platform; print(platform.python_version())"
).Trim()

$ObservedPip = (
    & $VenvPython -c "import importlib.metadata as m; print(m.version('pip'))"
).Trim()

$ObservedSetuptools = (
    & $VenvPython -c "import importlib.metadata as m; print(m.version('setuptools'))"
).Trim()

if ($ObservedPython -ne $RequiredPython) {
    throw "STOP: Python version drift."
}

if ($ObservedPip -ne $RequiredPip) {
    throw "STOP: pip version drift."
}

if ($ObservedSetuptools -ne $RequiredSetuptools) {
    throw "STOP: setuptools version drift."
}

& $VenvPython -m pip install `
    --disable-pip-version-check `
    --no-input `
    --no-build-isolation `
    --no-deps `
    --force-reinstall `
    .

if ($LASTEXITCODE -ne 0) {
    throw "STOP: TraceSOC build/install failed."
}

$ObservedTraceSoc = (
    & $VenvPython -c "import importlib.metadata as m; print(m.version('tracesoc'))"
).Trim()

if ($ObservedTraceSoc -ne $RequiredTraceSoc) {
    throw "STOP: installed TraceSOC version mismatch."
}

$CliHelp = @(
    & $VenvPython -m tracesoc --help 2>&1
)

if ($LASTEXITCODE -ne 0) {
    throw "STOP: installed TraceSOC CLI failed."
}

$CliHelpText = ($CliHelp -join "`n")

$HasExplain = (
    $CliHelpText -match '(?m)(^|[\s,{])explain([\s,}]|$)'
)

$HasCase = (
    $CliHelpText -match '(?m)(^|[\s,{])case([\s,}]|$)'
)

if (-not $HasExplain) {
    throw "STOP: installed TraceSOC CLI does not expose explain."
}

if (-not $HasCase) {
    throw "STOP: installed TraceSOC CLI does not expose case."
}

Write-Host "BUILD_RESULT=PASS"
Write-Host "TRACESOC_VERSION=$ObservedTraceSoc"
Write-Host "PRODUCT_CLI=python -m tracesoc"
