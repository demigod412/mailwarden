@echo off
setlocal

rem Mailwarden - one-click Windows SMTP-relay probe launcher.
rem Double-click this file, or run it from a terminal: probe.bat
rem
rem It actively probes smtp-relay.gmail.com to tell whether your relay accepts
rem bulk mail from any IP (no source-IP restriction). It ONLY probes domains you
rem have authorized in my-audit\authorization.json, makes an unauthenticated
rem connection, and stops before sending any message (nothing is delivered).
rem
rem IMPORTANT: run this from an internet connection whose IP is NOT in your own
rem sending ranges (e.g. a home/mobile hotspot or a cloud VM), or the "any IP"
rem result cannot be trusted. The tool warns you if it detects an in-range IP.

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
        pause
        exit /b 1
    )
)

if not exist "my-audit\domains.txt" (
    echo [setup] Writing example input files to my-audit\ ...
    mailwarden init my-audit
    echo.
    echo Starter files were created in my-audit\
    echo   1. Open my-audit\domains.txt and list your own domains ^(one per line^).
    echo   2. Open my-audit\authorization.json and add an entry for each domain
    echo      ^(set "authorized": true^). The probe ONLY runs for authorized domains.
    echo Then run this script again.
    pause
    exit /b 0
)

if not exist "my-audit\authorization.json" (
    echo.
    echo ERROR: my-audit\authorization.json is missing. The probe requires it so it
    echo only ever tests domains you are authorized to assess.
    echo.
    echo Fix: double-click authorize.bat first ^(it lists your domains and asks you to
    echo confirm you own them^), then run this script again.
    echo Or in a terminal: mailwarden authorize --from my-audit\domains.txt
    pause
    exit /b 1
)

set "CFG_FLAG="
if exist "my-audit\mailwarden.toml" set "CFG_FLAG=--config my-audit\mailwarden.toml"

echo.
echo [probe] Checking your public IP and probing smtp-relay.gmail.com ...
echo         ^(authorized domains only; unauthenticated; no message is sent^)
mailwarden %CFG_FLAG% scan --mode dns ^
  --domains my-audit\domains.txt ^
  --authorization my-audit\authorization.json ^
  --probe-relay ^
  --output mailwarden-output
if errorlevel 1 (
    echo.
    echo The run reported a problem ^(or a --fail-on gate^). See the message above.
    echo If it says "--probe-relay requires --authorization", edit my-audit\authorization.json.
    pause
    exit /b 1
)

echo.
echo [done] Opening the report. Check the "SMTP relay exploitability" tab and the
echo        "Relay probe" chip under each domain.
mailwarden serve --dir mailwarden-output

pause
