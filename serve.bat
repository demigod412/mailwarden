@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\mailwarden.exe" (
    echo ERROR: mailwarden is not installed yet. Run scan.bat first.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
mailwarden serve --dir mailwarden-output
pause
