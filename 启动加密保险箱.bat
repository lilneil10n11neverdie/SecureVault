@echo off
rem Secure Vault launcher (double-click to run)
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw secure_vault.py
    exit /b
)
py -3 secure_vault.py
