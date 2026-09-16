@echo off
setlocal EnableExtensions
chcp 65001 >nul
title ZumunciTravel-WEB

cd /d "%~dp0.."
set "ROOT=%cd%"

if not exist "%ROOT%\frontend\node_modules\" (
  echo [ERREUR] node_modules manquant. Lancez windows\INSTALLER.bat
  pause
  exit /b 1
)

cd /d "%ROOT%\frontend"
if not exist ".env.development" (
  echo VITE_API_URL=/api> ".env.development"
)

echo.
echo  Frontend ZumunciTravel — http://127.0.0.1:5173
echo  Ctrl+C pour arreter cette fenetre.
echo.

call npm run dev -- --host 127.0.0.1 --port 5173
pause
endlocal
