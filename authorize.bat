@echo off
setlocal enabledelayedexpansion

rem Mailwarden - one-click authorization for the domains in my-audit\domains.txt.
rem Double-click this file, or run it from a terminal: authorize.bat
rem
rem It marks every domain in my-audit\domains.txt as authorized so probe.bat can
rem actively test them. ONLY run this for domains you own or have written
rem permission to test. It asks you to confirm before writing anything.

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
    echo A starter file was created at my-audit\domains.txt
    echo Open it, list your own domains ^(one per line^), then run this script again.
    pause
    exit /b 0
)

rem Count the domains that will be authorized (non-empty, non-comment lines).
set /a COUNT=0
for /f "usebackq tokens=* delims= " %%L in ("my-audit\domains.txt") do (
    set "LINE=%%L"
    if not "!LINE!"=="" if not "!LINE:~0,1!"=="#" set /a COUNT+=1
)

if %COUNT%==0 (
    echo.
    echo my-audit\domains.txt has no domains in it yet. Add your domains ^(one per line^)
    echo and run this script again.
    pause
    exit /b 0
)

echo.
echo These %COUNT% domain(s) from my-audit\domains.txt will be marked AUTHORIZED:
echo -----------------------------------------------------------------------
type "my-audit\domains.txt"
echo -----------------------------------------------------------------------
echo.
echo Only continue if you OWN these domains or have WRITTEN PERMISSION to test them.
echo probe.bat will then actively test them against smtp-relay.gmail.com.
echo.

set "CONFIRM="
set /p CONFIRM="Type YES and press Enter to authorize them (anything else cancels): "
if /i not "!CONFIRM!"=="YES" (
    echo.
    echo Cancelled. Nothing was changed.
    pause
    exit /b 0
)

echo.
mailwarden authorize --from my-audit\domains.txt
if errorlevel 1 (
    echo.
    echo ERROR: authorization failed. See the message above.
    pause
    exit /b 1
)

echo.
echo [done] Authorized. Next: double-click probe.bat to test these domains.
echo        ^(Run probe.bat from an IP OUTSIDE your own sending ranges.^)
pause
