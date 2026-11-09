@echo off
REM AgenC Bridge — GitHub bus sync loop (Windows).
REM Usage: sync-windows.bat <bus-dir> <node> <project-root> [interval-seconds]
REM Requires: git, python, bridge.py beside this script, AGENC_BRIDGE_SECRET set,
REM OPENROUTER_API_KEY set.
set BUS=%1
set NODE=%2
set PROJECT=%3
set INTERVAL=%4
if "%INTERVAL%"=="" set INTERVAL=60
:loop
cd /d "%BUS%" && git pull --ff-only --quiet
python "%~dp0bridge.py" poll --bus "%BUS%" --node "%NODE%" --project-root "%PROJECT%"
cd /d "%BUS%" && git add -A && git commit -qm "bridge: %NODE%" && git push --quiet
timeout /t %INTERVAL% /nobreak >nul
goto loop
