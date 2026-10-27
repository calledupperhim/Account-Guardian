@echo off
title Account Guardian
cd /d "%~dp0"
where py >nul 2>nul && (py -3 guardian.py & goto end)
where python >nul 2>nul && (python guardian.py & goto end)
echo Python is not installed.
echo Install it free from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH" during setup), then double-click this file again.
start https://www.python.org/downloads/
:end
pause
