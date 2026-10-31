@echo off
rem ============================================================
rem  Start rustyshare with a double click
rem  - builds it first if no rustyshare.exe exists yet
rem  - runs in portable mode (profile in target\...\data)
rem  - opens the web UI in the browser
rem ============================================================
title rustyshare
cd /d "%~dp0"

rem OpenSSL from vcpkg (only needed when building)
if not defined VCPKG_ROOT set "VCPKG_ROOT=C:\vcpkg"
if not defined OPENSSL_DIR set "OPENSSL_DIR=%VCPKG_ROOT%\installed\x64-windows-static-md"
set "OPENSSL_STATIC=1"

rem portable mode keeps the profile next to the exe ("data" folder):
rem use the build that already has a profile, else release, else debug
set "EXE="
if exist "target\debug\data" if exist "target\debug\rustyshare.exe" set "EXE=target\debug\rustyshare.exe"
if not defined EXE if exist "target\release\data" if exist "target\release\rustyshare.exe" set "EXE=target\release\rustyshare.exe"
if not defined EXE if exist "target\release\rustyshare.exe" set "EXE=target\release\rustyshare.exe"
if not defined EXE if exist "target\debug\rustyshare.exe" set "EXE=target\debug\rustyshare.exe"

if not defined EXE (
    echo rustyshare.exe not found, building it now. This takes a few minutes ...
    cargo build
    if errorlevel 1 (
        echo.
        echo Build failed, see the errors above.
        pause
        exit /b 1
    )
    set "EXE=target\debug\rustyshare.exe"
)

echo Starting %EXE% ...
echo The web UI opens in your browser once you have logged in: http://127.0.0.1:9095
echo Close this window or press Ctrl+C to stop rustyshare.
echo.

rem open the browser a bit later, after the login prompt
rem (own minimized window, so it does not steal keyboard input from the login)
start "rustyshare browser" /min cmd /c "timeout /t 20 /nobreak >nul & start http://127.0.0.1:9095"

"%EXE%" --portable %*

echo.
echo rustyshare has stopped.
pause
