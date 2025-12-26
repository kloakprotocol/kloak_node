@echo off
setlocal
cd /d "%~dp0"

if exist ".\dist\KloakNode.exe" (
  .\dist\KloakNode.exe
) else (
  echo ERROR: .\dist\KloakNode.exe not found.
  echo Build it first by running: python build_exe.py
)

pause
