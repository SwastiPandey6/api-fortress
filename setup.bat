@echo off
REM API Fortress - one-time setup for Windows
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)
%PY% --version >nul 2>nul || (echo Python 3.10+ is required. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)

echo [1/4] Creating virtual environment .venv
if not exist .venv %PY% -m venv .venv || (echo Failed to create virtual environment & pause & exit /b 1)

echo [2/4] Installing dependencies
.venv\Scripts\python -m pip install --upgrade pip >nul
.venv\Scripts\python -m pip install -r requirements.txt || (echo Dependency installation failed & pause & exit /b 1)

echo [3/4] Creating .env
if not exist .env copy .env.example .env >nul

echo [4/4] Running test suite
.venv\Scripts\python -m pytest -q

echo.
echo Setup complete. Start the application with:  start.bat
pause
