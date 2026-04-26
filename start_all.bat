@echo off
echo ========================================================
echo FIRE DRILL: STARTING FULL IDS AUTO-DEFENSE PLATFORM
echo ========================================================

echo [1] Starting Main API Server (Port 5000)
start "API Backend" cmd /k "python.exe api.py"

echo [2] Starting Unified Agent ^& WebSocket Server (Port 8001)
start "Unified Agent" cmd /k "python.exe unified_agent.py --mode live"

echo [3] Starting Dashboard Frontend (Port 5173)
cd frontend
start "React Dashboard" cmd /k "npm run dev"
cd ..

echo [4] Starting AI Pentest Agent (Port 8088)
start "Pentest Agent" cmd /k "python.exe -m pentest_agent.app"

echo ========================================================
echo ALL SYSTEMS GO! Check your windows.
echo   - API Backend:    http://localhost:5000
echo   - WebSocket:      ws://localhost:8001
echo   - Dashboard:      http://localhost:5173
echo   - Pentest Agent:  http://localhost:8088
echo ========================================================
