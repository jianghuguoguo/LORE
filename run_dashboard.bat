@echo off
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Virtual environment not found. Please ensure .venv exists in the root directory.
    pause
    exit /b
)
cd /d "%~dp0"
echo [INFO] Starting Evo-Pentest Dashboard...
"%PYTHON_EXE%" -m dashboard.app
pause
