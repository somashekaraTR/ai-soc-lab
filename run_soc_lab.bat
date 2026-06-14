@echo off
echo ============================================
echo   AI SOC Lab - Running Full Pipeline
echo ============================================

echo.
echo [1/3] Generating synthetic logs...
python generate_logs.py

echo.
echo [2/3] Running AI triage model...
python ai_triage.py

echo.
echo [3/3] Building dashboard...
python build_dashboard.py

echo.
echo ============================================
echo   Done! Opening dashboard in browser...
echo ============================================
start soc_dashboard.html

pause
