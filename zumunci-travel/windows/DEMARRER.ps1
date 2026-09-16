# ZumunciTravel — demarrage PowerShell (alternative a DEMARRER.bat)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path "$Root\DEMARRER.bat")) {
  $Root = $PSScriptRoot
  if (-not (Test-Path "$Root\DEMARRER.bat")) {
    throw "Impossible de trouver DEMARRER.bat"
  }
}

Write-Host "Lancement de DEMARRER.bat ..." -ForegroundColor Cyan
Start-Process -FilePath "$Root\DEMARRER.bat" -WorkingDirectory $Root
