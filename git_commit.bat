@echo off
REM Script para hacer commit de cambios en Git
REM Uso: git_commit.bat "Mensaje del commit"

echo ========================================
echo Git Commit - Sistema de Facturacion Medico
echo ========================================
echo.

REM Buscar git en ubicaciones comunes
set GIT_PATH=
if exist "C:\Program Files\Git\bin\git.exe" set GIT_PATH=C:\Program Files\Git\bin\git.exe
if exist "C:\Program Files (x86)\Git\bin\git.exe" set GIT_PATH=C:\Program Files (x86)\Git\bin\git.exe
if exist "%LOCALAPPDATA%\Programs\Git\bin\git.exe" set GIT_PATH=%LOCALAPPDATA%\Programs\Git\bin\git.exe

if "%GIT_PATH%"=="" (
    echo ERROR: No se encontro Git instalado.
    echo Por favor, instala Git desde https://git-scm.com/download/win
    echo O agrega Git al PATH del sistema.
    pause
    exit /b 1
)

REM Si no se proporciono mensaje, pedirlo
if "%~1"=="" (
    set /p COMMIT_MSG="Ingresa el mensaje del commit: "
) else (
    set COMMIT_MSG=%~1
)

echo.
echo Agregando archivos al staging...
"%GIT_PATH%" add .

echo.
echo Estado de los cambios:
"%GIT_PATH%" status --short

echo.
echo Haciendo commit con mensaje: %COMMIT_MSG%
"%GIT_PATH%" commit -m "%COMMIT_MSG%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Commit realizado exitosamente!
    echo ========================================
) else (
    echo.
    echo ========================================
    echo ERROR: No se pudo realizar el commit
    echo ========================================
)

echo.
pause



