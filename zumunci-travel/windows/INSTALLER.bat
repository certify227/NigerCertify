@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
title ZumunciTravel — Installation Windows

cd /d "%~dp0.."
set "ROOT=%cd%"
set "QUIET=%~1"

echo.
echo  ============================================================
echo   Installation ZumunciTravel (Windows)
echo  ============================================================
echo.

call "%ROOT%\windows\check-deps.bat"
if errorlevel 1 (
  if /I not "%QUIET%"=="/quiet" pause
  exit /b 1
)

echo [1/2] Backend Python (venv + pip)...
if not exist "%ROOT%\backend\.venv\Scripts\python.exe" (
  echo       Creation du venv...
  %PY_CMD% -m venv "%ROOT%\backend\.venv"
  if errorlevel 1 (
    echo [ERREUR] Impossible de creer le venv Python.
    if /I not "%QUIET%"=="/quiet" pause
    exit /b 1
  )
)

"%ROOT%\backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
"%ROOT%\backend\.venv\Scripts\pip.exe" install -r "%ROOT%\backend\requirements.txt"
if errorlevel 1 (
  echo [ERREUR] pip install a echoue.
  if /I not "%QUIET%"=="/quiet" pause
  exit /b 1
)

if not exist "%ROOT%\backend\.env" (
  copy /Y "%ROOT%\windows\env.backend.example" "%ROOT%\backend\.env" >nul
)

echo [2/2] Frontend npm...
pushd "%ROOT%\frontend"
if not exist ".env.development" (
  echo VITE_API_URL=/api> ".env.development"
)
call npm install
if errorlevel 1 (
  popd
  echo [ERREUR] npm install a echoue.
  if /I not "%QUIET%"=="/quiet" pause
  exit /b 1
)
popd

echo.
echo  Installation terminee.
echo  Lancez DEMARRER.bat pour demarrer l'application.
echo.
if /I not "%QUIET%"=="/quiet" pause
endlocal
exit /b 0
