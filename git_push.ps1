# Script PowerShell para hacer push al repositorio remoto
# Uso: .\git_push.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Git Push - Sistema de Facturacion Medico" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Buscar git
$gitPaths = @(
    "C:\Program Files\Git\bin\git.exe",
    "C:\Program Files (x86)\Git\bin\git.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\git.exe",
    "git"
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
    Write-Host "ERROR: No se encontro Git." -ForegroundColor Red
    Read-Host "Presiona Enter para salir"
    exit 1
}

# Verificar si hay remoto configurado
Write-Host "Verificando remoto configurado..." -ForegroundColor Yellow
$remotes = & $gitExe remote -v

if ([string]::IsNullOrWhiteSpace($remotes)) {
    Write-Host ""
    Write-Host "No hay remoto configurado." -ForegroundColor Yellow
    Write-Host "Por favor, configura el remoto primero:" -ForegroundColor Yellow
    Write-Host "  git remote add origin URL_DEL_REPOSITORIO" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Ejemplo:" -ForegroundColor Yellow
    Write-Host "  git remote add origin https://github.com/usuario/Facturacion-Medica.git" -ForegroundColor Cyan
    Read-Host "Presiona Enter para salir"
    exit 1
}

Write-Host "Remoto encontrado:" -ForegroundColor Green
Write-Host $remotes -ForegroundColor Gray
Write-Host ""

# Verificar si hay commits para hacer push
$status = & $gitExe status -sb
if ($status -match "ahead") {
    Write-Host "Hay commits locales para subir." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Haciendo push..." -ForegroundColor Yellow
    & $gitExe push origin master
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Push realizado exitosamente!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "ERROR: No se pudo hacer push" -ForegroundColor Red
        Write-Host "Verifica tus credenciales o la URL del remoto" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Red
    }
} else {
    Write-Host "No hay commits nuevos para subir." -ForegroundColor Green
    Write-Host "Todo está sincronizado con el remoto." -ForegroundColor Green
}

Write-Host ""
Read-Host "Presiona Enter para salir"



