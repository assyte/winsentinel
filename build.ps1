[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipDeps
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

Write-Host "WinSentinel build" -ForegroundColor Cyan
Write-Host "Project: $PSScriptRoot"

if (-not $SkipDeps) {
    Write-Host "`nInstalling build dependencies..." -ForegroundColor Cyan
    python -m pip install --upgrade -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed with exit code $LASTEXITCODE."
    }
}

if ($Clean) {
    foreach ($path in @("build", "dist")) {
        if (Test-Path -LiteralPath $path) {
            Write-Host "Removing $path..." -ForegroundColor Yellow
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}

Write-Host "`nRunning PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean WinSentinel.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE."
}

$executable = Join-Path $PSScriptRoot "dist\WinSentinel.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Build completed but $executable was not produced."
}

$sizeMb = [math]::Round((Get-Item -LiteralPath $executable).Length / 1MB, 1)
Write-Host "`nBuilt $executable ($sizeMb MB)" -ForegroundColor Green
Write-Host "The executable requests administrator rights on launch." -ForegroundColor DarkGray
