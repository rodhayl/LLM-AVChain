@echo off
REM LLM-AVChain Proof-of-Concept -- Stop All Services
REM Stops all Python/uvicorn/streamlit processes started by start.bat.

set "NO_PAUSE=0"
if /I "%AVCHAIN_NO_PAUSE%"=="1" set "NO_PAUSE=1"
for %%A in (%*) do (
    if /I "%%~A"=="--no-pause" set "NO_PAUSE=1"
)

echo ============================================
echo  LLM-AVChain POC -- Stopping Services
echo ============================================

set "PYTHON_CMD=python"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe --version >nul 2>&1
    if not errorlevel 1 (
        .venv\Scripts\python.exe -c "import avchain" >nul 2>&1
        if not errorlevel 1 set "PYTHON_CMD=.venv\Scripts\python.exe"
    )
)

echo Stopping repo services...
%PYTHON_CMD% -m avchain.scripts.stop_services

echo.
echo ============================================
echo  All LLM-AVChain services stopped.
echo ============================================
echo NOTE: stop.bat only manages the host-started stack.
echo If Docker Compose is running, also use docker compose down -v --remove-orphans.
if "%NO_PAUSE%"=="1" exit /b 0
pause
exit /b 0
