@echo off
cls
echo ========================================
echo   Kloak Node Installer
echo ========================================
echo.

REM If a standalone EXE is present, Python install is not needed
if exist "dist\KloakNode.exe" (
    echo Found standalone executable: dist\KloakNode.exe
    echo.
    echo Python is NOT required for the standalone .exe release.
    echo To run, either:
    echo   - Or run: dist\KloakNode.exe
    echo.
    pause
    exit /b 0
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found!
    echo.
    echo Please install Python 3.11 or 3.12 from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    echo Note: If you are using the standalone .exe release, Python is not required.
    pause
    exit /b 1
)

echo [1/4] Checking Python version...
python --version
echo.
echo If you run into dependency install issues, try Python 3.11 or 3.12.
echo.
timeout /t 5

echo.
echo [2/4] Creating virtual environment...
python -m venv .venv
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment!
    pause
    exit /b 1
)

echo.
echo [3/4] Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo [4/4] Installing dependencies...
pip install --quiet --upgrade pip
pip install kaspy==0.0.13 websockets cryptography mnemonic ecdsa base58 qrcode

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo To run Kloak Node:
echo   Option 1: Build the EXE: python build_exe.py
echo            Then run: run_kloak.bat
echo   Option 2: From terminal: .venv\Scripts\activate.bat
echo                            python kloak_node.py
echo.
pause
