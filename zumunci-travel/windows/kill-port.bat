@echo off
REM Tue le processus qui ECOUTE sur le port %1
set "PORT=%~1"
if "%PORT%"=="" exit /b 1

for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":%PORT% .*LISTENING"') do (
  echo  - Port %PORT% : arret PID %%P
  taskkill /F /PID %%P >nul 2>&1
)
exit /b 0
