@echo off
REM Detecte Python et Node ; exporte PY_CMD
set "PY_CMD="

where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
  if not errorlevel 1 set "PY_CMD=py -3"
)

if not defined PY_CMD (
  where python >nul 2>&1
  if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
  )
)

if not defined PY_CMD (
  echo [ERREUR] Python 3.10+ introuvable.
  echo          Installez Python depuis https://www.python.org/downloads/
  echo          Cochez "Add python.exe to PATH" pendant l'installation.
  exit /b 1
)

where node >nul 2>&1
if errorlevel 1 (
  echo [ERREUR] Node.js introuvable.
  echo          Installez LTS depuis https://nodejs.org/
  exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
  echo [ERREUR] npm introuvable (installe avec Node.js).
  exit /b 1
)

for /f "tokens=*" %%i in ('%PY_CMD% -c "import sys; print(sys.version.split()[0])"') do set "PY_VER=%%i"
for /f "tokens=*" %%i in ('node -v') do set "NODE_VER=%%i"
echo [OK] Python %PY_VER%  ^|  Node %NODE_VER%
exit /b 0
