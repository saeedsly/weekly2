@echo off
setlocal
cd /d "%~dp0"
set "HOST=127.0.0.1"
set "PORT=8000"
set "NODE_ENV=development"
set "AUTH_DEV_MODE=true"
set "ALLOW_FIRST_ADMIN=true"
set "DEV_AUTO_APPROVE_USERS=true"
echo HamYar local demo is starting. Demo OTPs appear in the browser and terminal; demo signups auto-activate.
echo Do NOT use this script for real organization data or production.
node --version
if errorlevel 1 (
  echo Node.js is not installed or is not available in PATH.
  echo Install Node.js 20 or 22 LTS, then reopen this window.
  pause
  exit /b 1
)
npm start
pause
