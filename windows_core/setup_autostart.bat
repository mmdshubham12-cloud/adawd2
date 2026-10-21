@echo off
title Kiarash Security System - Windows AutoStart & Power Setup
echo Configuring Windows Power Plan (Never Sleep / High Performance)...
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 15
powercfg /change hibernate-timeout-ac 0

echo Adding KiarashSecurityCore to Windows Startup...
set "STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "APP_PATH=%~dp0dist\KiarashSecurityCore\KiarashSecurityCore.exe"

powershell "$s=(New-Object -COM WScript.Shell).CreateShortcut('%STARTUP_FOLDER%\KiarashSecurityCore.lnk');$s.TargetPath='%APP_PATH%';$s.WorkingDirectory='%~dp0dist\KiarashSecurityCore';$s.Save()"

echo.
echo [IMPORTANT BIOS NOTE]:
echo To make the PC turn on automatically when electricity returns after a power outage:
echo 1. Restart PC and press DEL / F2 to enter BIOS.
echo 2. Go to Power Management / APM Configuration.
echo 3. Set "Restore on AC/Power Loss" to "Power On" (or "Always On").
echo.
pause
