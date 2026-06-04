@echo off
setlocal
cd /d "%~dp0"

echo ========================================================
echo FUSION STRIKE AI: STARTING DEMO PLATFORM
echo ========================================================

set PY=%CD%\.venv\Scripts\python.exe
if not exist "%PY%" (
  echo [ERROR] .venv was not found. Create it first, then install dependencies.
  echo         Expected: %PY%
  pause
  exit /b 1
)

echo [1] Starting Main API Server (Port 5000)
start "API Backend :5000" cmd /k ""%PY%" api.py"

echo [2] Preparing demo data if database is empty
"%PY%" tools\demo_seed.py

echo [3] WebSocket Dashboard API is owned by Unified IDS Agent (Port 8001)
echo     Not starting dashboard_api.py separately to avoid duplicate port binding.

echo [4] Starting Dashboard Frontend (Port 4173)
if not exist "frontend\dist\index.html" (
  echo     frontend\dist missing - building once...
  pushd frontend
  call npm.cmd run build
  popd
)
start "Dashboard :4173" cmd /k ""%PY%" serve_frontend.py"

echo [5] Starting Unified IDS Agent + WebSocket Server
start "Unified IDS Agent" cmd /k ""%PY%" unified_agent.py --mode live"

echo ========================================================
echo ALL SYSTEMS GO! Check your windows.
echo   - API Backend:    http://localhost:5000
echo   - WebSocket API:   http://localhost:8001/api/metrics
echo   - WS Stream:       ws://localhost:8001/ws/live
echo   - Dashboard:       http://localhost:4173
echo   - Pentest:         POST http://localhost:5000/pentest/scan
echo ========================================================
pause
