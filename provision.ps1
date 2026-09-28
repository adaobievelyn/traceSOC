param(
    [string]$PythonExe = 'python'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Repo '.venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

$RequiredPython = '3.13.14'
$RequiredPip = '26.1.2'
$RequiredSetuptools = '84.0.0'

Set-Location -LiteralPath $Repo

if (Test-Path -LiteralPath $Venv) {
    throw "STOP: .venv already exists. Run clean.ps1 first."
}

$Resolved = Get-Command $PythonExe -ErrorAction Stop

$BasePython = $Resolved.Source

if ([string]::IsNullOrWhiteSpace($BasePython)) {
    $BasePython = $Resolved.Path
}

if ([string]::IsNullOrWhiteSpace($BasePython)) {
    throw "STOP: could not resolve base Python executable."
}

$ObservedPython = (
    & $BasePython -c "import platform; print(platform.python_version())" 2>&1 |
    Out-String
).Trim()

if ($LASTEXITCODE -ne 0) {
    throw "STOP: base Python version query failed."
}

if ($ObservedPython -ne $RequiredPython) {
    throw "STOP: supported Python is exactly $RequiredPython; observed $ObservedPython"
}

& $BasePython -m venv $Venv

if ($LASTEXITCODE -ne 0) {
    throw "STOP: virtual environment creation failed."
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    throw "STOP: virtual environment Python missing."
}

& $VenvPython -m pip install `
    --disable-pip-version-check `
    --no-input `
    "pip==$RequiredPip"

if ($LASTEXITCODE -ne 0) {
    throw "STOP: exact pip installation failed."
}

& $VenvPython -m pip install `
    --disable-pip-version-check `
    --no-input `
    "setuptools==$RequiredSetuptools"

if ($LASTEXITCODE -ne 0) {
    throw "STOP: exact setuptools installation failed."
}

$ObservedPip = (
    & $VenvPython -c "import importlib.metadata as m; print(m.version('pip'))"
).Trim()

$ObservedSetuptools = (
    & $VenvPython -c "import importlib.metadata as m; print(m.version('setuptools'))"
).Trim()

if ($ObservedPip -ne $RequiredPip) {
    throw "STOP: pip pin verification failed."
}

if ($ObservedSetuptools -ne $RequiredSetuptools) {
    throw "STOP: setuptools pin verification failed."
}

Write-Host "PROVISION_RESULT=PASS"
Write-Host "PYTHON_VERSION=$ObservedPython"
Write-Host "PIP_VERSION=$ObservedPip"
Write-Host "SETUPTOOLS_VERSION=$ObservedSetuptools"
