@echo off
title TrustVault Secure Document Sharing
echo ============================================================
echo   Starting TrustVault Secure Repository...
echo ============================================================
cd /d "C:\Users\Fam\.gemini\antigravity\scratch\trustvault"
"C:\Users\Fam\AppData\Local\Programs\Python\Python314\python.exe" run.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Server encountered an issue starting.
    pause
)
