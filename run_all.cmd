@echo off
setlocal

cd /d "%~dp0"

set PYTHON=.venv\Scripts\python.exe

if not exist "%PYTHON%" (
  echo .venv not found. Create it or update the script.
  exit /b 1
)

echo Starting DB on 8001...
start "DB" /B "%PYTHON%" -m uvicorn DB.main:app --port 8001 --reload

echo Starting API on 8000...
start "API" /B "%PYTHON%" -m uvicorn API.main:app --port 8000 --reload

echo Starting Frontend on 8002...
start "Frontend" /B "%PYTHON%" -m uvicorn Frontend.main:app --port 8002 --reload

echo Done. Close this window to stop all.
