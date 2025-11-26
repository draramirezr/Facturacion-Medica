@echo off
echo ================================================
echo   REINICIANDO SERVIDOR DE FACTURACION MEDICA
echo ================================================
echo.

REM Matar todos los procesos de Python
echo [1/3] Deteniendo procesos de Python anteriores...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM py.exe 2>nul
timeout /t 2 /nobreak >nul

echo.
echo [2/3] Limpiando cache de templates...
if exist templates\__pycache__ rd /s /q templates\__pycache__
if exist __pycache__ rd /s /q __pycache__

echo.
echo [3/3] Iniciando servidor Flask...
echo.
echo ================================================
echo   SERVIDOR INICIADO
echo   URL: http://localhost:5000
echo   Presiona Ctrl+C para detener
echo ================================================
echo.

py app.py

pause









