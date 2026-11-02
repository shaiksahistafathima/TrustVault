@echo off
title TrustVault Security Test Suite
echo ============================================================
echo   Running TrustVault Adversarial Security Test Suite...
echo ============================================================
cd /d "C:\Users\Fam\.gemini\antigravity\scratch\trustvault"
"C:\Users\Fam\AppData\Local\Programs\Python\Python314\python.exe" -m unittest discover -s tests
echo.
pause
