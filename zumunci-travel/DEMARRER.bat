@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
title ZumunciTravel — Démarrage Windows

REM =============================================================================
REM  ZumunciTravel — lanceur Windows (API + Frontend)
REM  Double-cliquez ce fichier pour démarrer l'instance locale.
REM =============================================================================

cd /d "%~dp0"
set "ROOT=%cd%"
set "API_PORT=8000"
set "WEB_PORT=5173"
set "API_URL=http://127.0.0.1:%API_PORT%"
set "WEB_URL=http://127.0.0.1:%WEB_PORT%"

echo.
echo  ============================================================
echo   ZumunciTravel — instance Windows
echo   Transport securise au Niger
echo  ============================================================
echo.

call "%ROOT%\windows\check-deps.bat"
if errorlevel 1 (
  echo.
  echo [ERREUR] Dependances manquantes. Lancez d'abord windows\INSTALLER.bat
  echo.
  pause
  exit /b 1
)

if not exist "%ROOT%\backend\.venv\Scripts\python.exe" (
  echo [INFO] Environnement Python absent — installation automatique...
  call "%ROOT%\windows\INSTALLER.bat" /quiet
  if errorlevel 1 (
    pause
    exit /b 1
  )
)

if not exist "%ROOT%\frontend\node_modules\" (
  echo [INFO] Dependances npm absentes — installation automatique...
  call "%ROOT%\windows\INSTALLER.bat" /quiet
  if errorlevel 1 (
    pause
    exit /b 1
  )
)

if not exist "%ROOT%\frontend\.env.development" (
  echo VITE_API_URL=/api> "%ROOT%\frontend\.env.development"
)

if not exist "%ROOT%\backend\.env" (
  copy /Y "%ROOT%\windows\env.backend.example" "%ROOT%\backend\.env" >nul
)

echo [1/3] Demarrage API FastAPI sur %API_URL% ...
start "ZumunciTravel-API" /D "%ROOT%\backend" cmd /k call "%ROOT%\windows\start-api.bat"

echo [2/3] Attente API ...
set /a _tries=0
:wait_api
set /a _tries+=1
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing '%API_URL%/api/health' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto api_ready
if !_tries! GEQ 40 (
  echo [ERREUR] L'API ne repond pas sur le port %API_PORT%.
  echo          Verifiez la fenetre ZumunciTravel-API.
  pause
  exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_api

:api_ready
echo       API OK.

echo [3/3] Demarrage Frontend Vite sur %WEB_URL% ...
start "ZumunciTravel-WEB" /D "%ROOT%\frontend" cmd /k call "%ROOT%\windows\start-web.bat"

echo.
echo  ------------------------------------------------------------
echo   Application  : %WEB_URL%
echo   API / docs   : %API_URL%/docs
echo   Compte demo  : 90000002 / zumunci123
echo   Admin KYC    : 90000099 / zumunci123
echo  ------------------------------------------------------------
echo   Pour arreter : double-cliquez ARRETER.bat
echo  ------------------------------------------------------------
echo.

timeout /t 3 /nobreak >nul
start "" "%WEB_URL%"

echo Pret. Les services tournent dans des fenetres separees.
echo Vous pouvez fermer cette fenetre.
echo.
pause
endlocal
exit /b 0
