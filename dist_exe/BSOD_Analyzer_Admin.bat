@echo off
REM BSOD Analyzer - Run as Administrator
REM This batch file ensures the application runs with admin privileges

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "EXE_PATH=%SCRIPT_DIR%BSOD_Analyzer.exe"

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    REM Re-launch as administrator
    powershell -Command "Start-Process -FilePath '%EXE_PATH%' -Verb RunAs"
    exit /b 0
) else (
    REM Already admin - just run it
    start "" "%EXE_PATH%"
    exit /b 0
)
