@echo off
setlocal

rem Mailwarden - one-click Windows scan launcher.
rem Double-click this file, or run it from a terminal: scan.bat

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [setup] No virtual environment found. Creating one now...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo.
        echo ERROR: could not create the virtual environment.
        echo Make sure Python 3.11+ is installed and on PATH: https://python.org/downloads
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"

if not exist ".venv\Scripts\mailwarden.exe" (
    echo [setup] Installing mailwarden and its dependencies...
    pip install -e ".[dev]"
    if errorlevel 1 (
        echo.
        echo ERROR: pip install failed. Scroll up to see the actual error above.
        echo Common fixes:
        echo   - check your internet connection
        echo   - run: python -m pip install --upgrade pip
        echo   - then run this script again
        pause
        exit /b 1
    )
    if not exist ".venv\Scripts\mailwarden.exe" (
        echo.
        echo ERROR: pip install finished but the mailwarden command still was not created.
        echo Try running manually: pip install -e ".[dev]"  and read any error shown.
        pause
        exit /b 1
    )
)

if not exist "my-audit\domains.txt" (
    echo [setup] Writing example input files to my-audit\ ...
    mailwarden init my-audit
    if errorlevel 1 (
        echo.
        echo ERROR: "mailwarden init" failed. Run it manually to see why:
        echo   .venv\Scripts\activate
        echo   mailwarden init my-audit
        pause
        exit /b 1
    )
    if not exist "my-audit\domains.txt" (
        echo.
        echo ERROR: my-audit\domains.txt still was not created. Something is wrong
        echo with this install. Try deleting the .venv folder and running this script again.
        pause
        exit /b 1
    )
    echo.
    echo A starter file was created at my-audit\domains.txt
    echo Open it, replace example.com with your own domains ^(one per line^), then run this script again.
    pause
    exit /b 0
)

set "CFG_FLAG="
if exist "my-audit\mailwarden.toml" set "CFG_FLAG=--config my-audit\mailwarden.toml"

echo.
echo [scan] Running DNS-only scan against domains in my-audit\domains.txt ...
mailwarden %CFG_FLAG% scan --domains my-audit\domains.txt --mode dns --output mailwarden-output
if errorlevel 1 (
    echo.
    echo ERROR: the scan failed. See the message above for details.
    pause
    exit /b 1
)

echo.
echo [done] Opening the report in your browser...
mailwarden serve --dir mailwarden-output

pause
