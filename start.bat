@echo off
REM LLM-AVChain Proof-of-Concept -- Start All Services
REM Run this script from the repository root directory.

set "NO_PAUSE=0"
set "SKIP_INSTALL=0"
if /I "%AVCHAIN_NO_PAUSE%"=="1" set "NO_PAUSE=1"
if /I "%AVCHAIN_SKIP_INSTALL%"=="1" set "SKIP_INSTALL=1"
for %%A in (%*) do (
    if /I "%%~A"=="--no-pause" set "NO_PAUSE=1"
    if /I "%%~A"=="--skip-install" set "SKIP_INSTALL=1"
)

echo ============================================
echo  LLM-AVChain POC -- Starting Services
echo ============================================

REM Create virtual environment if it does not exist
if not exist .venv (
    if "%SKIP_INSTALL%"=="1" (
        echo ERROR: Virtual environment missing; cannot use --skip-install.
        goto startup_failed
    )
    python --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python not found. Install Python 3.12+ and add to PATH.
        goto startup_failed
    )
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 goto startup_failed
)

REM Use the selected interpreter directly; activation scripts are not required.
set "VENV_PYTHON=%CD%\.venv\Scripts\python.exe"
if not exist "%VENV_PYTHON%" (
    echo ERROR: Virtual environment interpreter missing. Repair .venv before starting.
    goto startup_failed
)
"%VENV_PYTHON%" --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Virtual environment interpreter failed. Repair .venv before starting.
    goto startup_failed
)

REM Install/update dependencies
if "%SKIP_INSTALL%"=="1" (
    echo Skipping dependency install...
) else (
    echo Installing dependencies...
    "%VENV_PYTHON%" -m pip install -e ".[dev,test]" -q
    if errorlevel 1 goto startup_failed
)

REM Ensure the project package is importable without falling back to PATH Python.
"%VENV_PYTHON%" -c "import avchain"
if errorlevel 1 goto startup_failed

REM Stop any stale repo services before launching a fresh stack
"%VENV_PYTHON%" -m avchain.scripts.stop_services
if errorlevel 1 goto startup_failed

REM Create data directories
if not exist data\evidence mkdir data\evidence
if not exist runtime mkdir runtime

REM Copy .env if not present
if not exist .env (
    echo Copying .env.example to .env...
    copy /Y .env.example .env >nul
)

REM Generate validator registry and keys if they do not exist
if not exist runtime\validators.yaml (
    echo Generating validator registry and keys...
    "%VENV_PYTHON%" -m avchain.scripts.generate_keys 3 runtime
    if errorlevel 1 goto startup_failed
)

REM Initialize database
echo Initializing database...
"%VENV_PYTHON%" -c "from avchain.database.core import init_db; init_db()"
if errorlevel 1 goto startup_failed

REM Validate runtime prerequisites and fail early on port conflicts
echo Running startup preflight...
"%VENV_PYTHON%" -m avchain.scripts.start_services --preflight
if errorlevel 1 (
    echo ERROR: Startup preflight failed.
    goto startup_failed
)

REM Start detached service supervisor
echo Starting detached service supervisor...
start "" /min "%VENV_PYTHON%" -m avchain.scripts.start_services
if errorlevel 1 goto startup_failed

REM Wait until the advertised endpoints are actually reachable
echo Waiting for services to become reachable...
"%VENV_PYTHON%" -m avchain.scripts.start_services --wait-ready
if errorlevel 1 (
    echo ERROR: Services did not become ready.
    "%VENV_PYTHON%" -m avchain.scripts.stop_services
    goto startup_failed
)

echo.
echo ============================================
echo  All services started.
echo  Ledger:     http://127.0.0.1:8000/docs
echo  Evidence:   http://127.0.0.1:8001/docs
echo  Consensus:  http://127.0.0.1:8002/docs
echo  Coverage:   http://127.0.0.1:8003/docs
echo  Dashboard:  http://127.0.0.1:8501
echo  Logs:       runtime\logs\
echo  Status:     runtime\status\
echo ============================================
echo.
echo Run stop.bat to shut down all services.
echo Run .venv\Scripts\python.exe -m avchain.scripts.run_demo to execute the local demo.
if "%NO_PAUSE%"=="1" exit /b 0
echo Press any key to keep this window open...
pause >nul
exit /b 0

:startup_failed
if "%NO_PAUSE%"=="1" exit /b 1
pause
exit /b 1
