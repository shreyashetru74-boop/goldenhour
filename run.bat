@echo off
REM GoldenHour: double-click to start (Windows)
cd /d "%~dp0"
if not exist .venv python -m venv .venv
.venv\Scripts\python -m pip install -q -r requirements.txt
.venv\Scripts\python goldenhour.py
pause
