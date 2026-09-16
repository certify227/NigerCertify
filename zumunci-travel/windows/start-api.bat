@echo off
setlocal EnableExtensions
chcp 65001 >nul
title ZumunciTravel-API

cd /d "%~dp0.."
set "ROOT=%cd%"

if not exist "%ROOT%\backend\.venv\Scripts\uvicorn.exe" (
  echo [ERREUR] uvicorn introuvable. Lancez windows\INSTALLER.bat
  pause
  exit /b 1
)

cd /d "%ROOT%\backend"
set "RESET_DB_ON_START=false"
set "APP_ENV=development"

echo.
echo  API ZumunciTravel — http://127.0.0.1:8000
echo  Docs               — http://127.0.0.1:8000/docs
echo  Ctrl+C pour arreter cette fenetre.
echo.

"%ROOT%\backend\.venv\Scripts\uvicorn.exe" app.main:app --host 127.0.0.1 --port 8000 --reload
pause
endlocal
