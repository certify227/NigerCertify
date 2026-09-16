@echo off
setlocal EnableExtensions
chcp 65001 >nul
title ZumunciTravel — Arrêt

cd /d "%~dp0"

echo.
echo  Arret de ZumunciTravel (ports 8000 et 5173)...
echo.

call "%~dp0windows\kill-port.bat" 8000
call "%~dp0windows\kill-port.bat" 5173

REM Ferme aussi les fenêtres cmd nommées si encore ouvertes
taskkill /FI "WINDOWTITLE eq ZumunciTravel-API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq ZumunciTravel-WEB*" /F >nul 2>&1

echo.
echo  Termine.
echo.
pause
endlocal
exit /b 0
