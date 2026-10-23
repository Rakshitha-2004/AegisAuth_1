@echo off
title AegisAuth Zero-Trust Launcher
echo ========================================================
echo        STARTING AEGISAUTH ZERO-TRUST SYSTEM
echo ========================================================
echo.

cd /d "C:\Users\Rakshitha B\.gemini\antigravity\scratch\AegisAuth"

echo [1/3] Checking MongoDB...
net start MongoDB >nul 2>&1

echo [2/3] Starting Zero-Trust Backend (Port 5000)...
start "AegisAuth-Backend" /min cmd /c "cd /d backend && python app.py"

timeout /t 2 >nul

echo [3/3] Starting AegisAuth Web Console (Port 5173)...
start "AegisAuth-Frontend" /min cmd /c "cd /d frontend && node serve_all.js"

timeout /t 2 >nul

echo [+] Launching AegisAuth in Chrome...
start "" "http://localhost:5173"

echo.
echo ========================================================
echo   AEGISAUTH IS RUNNING AT: http://localhost:5173
echo   (Keep this window minimized during your viva)
echo ========================================================
pause
