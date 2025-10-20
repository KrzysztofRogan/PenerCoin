@echo off
REM ============================================
REM  Start local P2P blockchain nodes (PenerCoin)
REM  Each node runs in its own PowerShell window
REM  Activates venv from C:\Users\Krzys\Studia
REM ============================================

echo Starting local P2P blockchain nodes...
echo ----------------------------------------
timeout /t 2 >nul

REM === Ścieżki ===
set VENV_PATH=C:\Users\Krzys\Studia\venv
set PROJECT_PATH=C:\Users\Krzys\Studia\PenerCoin

REM === Node 1 ===
start "Node 1" powershell -NoExit -Command "cd '%PROJECT_PATH%'; & '%VENV_PATH%\Scripts\Activate.ps1'; python node.py 8765"

REM === Node 2 (connects to Node 1) ===
timeout /t 2 >nul
start "Node 2" powershell -NoExit -Command "cd '%PROJECT_PATH%'; & '%VENV_PATH%\Scripts\Activate.ps1'; python node.py 8766 ws://localhost:8765"

REM === Node 3 (connects to Node 1 and 2) ===
timeout /t 2 >nul
start "Node 3" powershell -NoExit -Command "cd '%PROJECT_PATH%'; & '%VENV_PATH%\Scripts\Activate.ps1'; python node.py 8767 ws://localhost:8766"

echo ----------------------------------------
echo All nodes started! Press any key to close this window.
pause >nul
