# Script PowerShell para hacer commit de cambios en Git
# Uso: .\git_commit.ps1 "Mensaje del commit"

param(
    [string]$Mensaje = ""
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Git Commit - Sistema de Facturacion Medico" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Buscar git en ubicaciones comunes
$gitPaths = @(
    "C:\Program Files\Git\bin\git.exe",
    "C:\Program Files (x86)\Git\bin\git.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\git.exe",
    "git"  # Intentar si está en PATH
)

$gitExe = $null
foreach ($path in $gitPaths) {
    if ($path -eq "git") {
        try {
            $gitExe = Get-Command git -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
            if ($gitExe) { break }
        } catch {
            continue
        }
    } else {
        if (Test-Path $path) {
            $gitExe = $path
            break
        }
    }
}

if (-not $gitExe) {
    Write-Host "ERROR: No se encontro Git instalado." -ForegroundColor Red
    Write-Host "Por favor, instala Git desde https://git-scm.com/download/win" -ForegroundColor Yellow
    Write-Host "O agrega Git al PATH del sistema." -ForegroundColor Yellow
    Read-Host "Presiona Enter para salir"
    exit 1
}

# Si no se proporcionó mensaje, pedirlo
if ([string]::IsNullOrWhiteSpace($Mensaje)) {
    $Mensaje = Read-Host "Ingresa el mensaje del commit"
}

if ([string]::IsNullOrWhiteSpace($Mensaje)) {
    Write-Host "ERROR: El mensaje del commit no puede estar vacio." -ForegroundColor Red
    Read-Host "Presiona Enter para salir"
    exit 1
}

Write-Host ""
Write-Host "Agregando archivos al staging..." -ForegroundColor Yellow
& $gitExe add .

Write-Host ""
Write-Host "Estado de los cambios:" -ForegroundColor Yellow
& $gitExe status --short

Write-Host ""
Write-Host "Haciendo commit con mensaje: $Mensaje" -ForegroundColor Yellow
& $gitExe commit -m $Mensaje

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Commit realizado exitosamente!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "ERROR: No se pudo realizar el commit" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

Write-Host ""
Read-Host "Presiona Enter para salir"





