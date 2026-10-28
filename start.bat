@echo off
REM API Fortress - start gateway (8000) and protected demo API (9000)
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run setup.bat first. & pause & exit /b 1)
start "" http://127.0.0.1:8000/dashboard
.venv\Scripts\python run_local.py %*
