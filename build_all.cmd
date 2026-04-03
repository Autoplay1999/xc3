@echo off
setlocal enabledelayedexpansion

:: Simple wrapper script for build.py
python "%~dp0build.py" %*

:: Propagate return code
exit /b %ERRORLEVEL%
