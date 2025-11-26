@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ================================================
echo   INICIANDO SISTEMA DE FACTURACION MEDICA
echo ================================================
echo.

py app.py

pause









