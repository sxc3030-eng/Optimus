@echo off
:: ═══════════════════════════════════════════════════════
::  NetGuard Pro — Create Linux Boot USB
::  Downloads Ubuntu + Rufus, creates bootable USB key
:: ═══════════════════════════════════════════════════════

title NetGuard Pro - Linux USB Creator
color 0A

echo.
echo   ╔═══════════════════════════════════════════════╗
echo   ║  NetGuard Pro — Linux USB Boot Creator        ║
echo   ╚═══════════════════════════════════════════════╝
echo.
echo   This will create a bootable Ubuntu USB key
echo   with NetGuard Pro pre-loaded.
echo.
echo   Requirements:
echo     - USB key 8GB minimum (will be ERASED)
echo     - Internet connection
echo.
pause

:: ── Check for downloads folder ──────────────────────
set DOWNLOAD_DIR=%~dp0linux_boot
if not exist "%DOWNLOAD_DIR%" mkdir "%DOWNLOAD_DIR%"

:: ── Download Rufus (portable) ───────────────────────
echo.
echo [1/3] Downloading Rufus (USB creator)...
if not exist "%DOWNLOAD_DIR%\rufus.exe" (
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/pbatard/rufus/releases/download/v4.6/rufus-4.6p.exe' -OutFile '%DOWNLOAD_DIR%\rufus.exe'"
    if errorlevel 1 (
        echo [!] Failed to download Rufus.
        echo     Download manually: https://rufus.ie
        echo     Save as: %DOWNLOAD_DIR%\rufus.exe
        pause
        exit /b 1
    )
)
echo [OK] Rufus ready.

:: ── Download Ubuntu ISO ─────────────────────────────
echo.
echo [2/3] Downloading Ubuntu 24.04 LTS ISO (about 5GB)...
echo         This may take a while...
if not exist "%DOWNLOAD_DIR%\ubuntu.iso" (
    powershell -Command "Write-Host 'Downloading Ubuntu ISO...' ; Invoke-WebRequest -Uri 'https://releases.ubuntu.com/24.04.2/ubuntu-24.04.2-desktop-amd64.iso' -OutFile '%DOWNLOAD_DIR%\ubuntu.iso'"
    if errorlevel 1 (
        echo [!] Failed to download Ubuntu ISO.
        echo     Download manually: https://ubuntu.com/download/desktop
        echo     Save as: %DOWNLOAD_DIR%\ubuntu.iso
        pause
        exit /b 1
    )
)
echo [OK] Ubuntu ISO ready.

:: ── Create NetGuard auto-install script ─────────────
echo.
echo [3/3] Preparing NetGuard Pro files...

:: Create a script that will auto-install NetGuard after Ubuntu boots
(
echo #!/bin/bash
echo # NetGuard Pro — Auto-installer for Ubuntu Live USB
echo # Run this after booting Ubuntu from USB:
echo #   bash /media/*/NETGUARD/install_netguard.sh
echo.
echo echo ""
echo echo "  ╔═══════════════════════════════════════════════╗"
echo echo "  ║  NetGuard Pro — Ubuntu Auto-Installer         ║"
echo echo "  ╚═══════════════════════════════════════════════╝"
echo echo ""
echo.
echo # Find the USB drive with NetGuard files
echo NETGUARD_DIR=""
echo for d in /media/*/NETGUARD /media/*/*/NETGUARD; do
echo     if [ -d "$d" ]; then
echo         NETGUARD_DIR="$d"
echo         break
echo     fi
echo done
echo.
echo if [ -z "$NETGUARD_DIR" ]; then
echo     echo "[!] NetGuard files not found on USB."
echo     echo "    Copy NetGuardPro-Linux folder to USB as NETGUARD"
echo     exit 1
echo fi
echo.
echo echo "[*] Found NetGuard at: $NETGUARD_DIR"
echo cp -r "$NETGUARD_DIR" ~/NetGuardPro
echo cd ~/NetGuardPro
echo chmod +x install.sh
echo sudo ./install.sh
echo echo ""
echo echo "[OK] NetGuard Pro installed! Launch with:"
echo echo "    ./launchers/lancer_netguard.sh"
) > "%DOWNLOAD_DIR%\install_netguard.sh"

echo [OK] Files prepared.

:: ── Instructions ────────────────────────────────────
echo.
echo   ============================================
echo     NEXT STEPS:
echo   ============================================
echo.
echo   1. Plug in your USB key (8GB minimum)
echo   2. Rufus will open now
echo   3. In Rufus:
echo      - Device: select your USB key
echo      - Boot selection: click SELECT
echo      - Choose: %DOWNLOAD_DIR%\ubuntu.iso
echo      - Click START
echo      - Wait for it to finish
echo.
echo   4. After Rufus finishes:
echo      - Copy the folder "NetGuardPro-Linux" to the USB key
echo      - Rename it to "NETGUARD"
echo.
echo   5. To boot from USB:
echo      - Restart PC
echo      - Press F12 / F2 / F8 / DEL at startup
echo        (depends on your PC brand)
echo      - Select USB in boot menu
echo      - Choose "Try Ubuntu"
echo.
echo   6. Once in Ubuntu, open Terminal and run:
echo      bash /media/*/NETGUARD/install_netguard.sh
echo.
echo   ============================================
echo.

:: ── Launch Rufus ────────────────────────────────────
echo Opening Rufus...
start "" "%DOWNLOAD_DIR%\rufus.exe"

pause
