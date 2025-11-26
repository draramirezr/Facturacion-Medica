@echo off
echo ================================================
echo   CREANDO ARCHIVO DE CONFIGURACION .env
echo ================================================
echo.

(
echo # Configuracion MySQL - Railway
echo MYSQL_URL=mysql://root:fmeSFyRCOODoDuPINTxYyzWatYzxxGCt@ballast.proxy.rlwy.net:10669/facturacion_medica
echo.
echo # Configuracion Separada
echo MYSQL_HOST=ballast.proxy.rlwy.net
echo MYSQL_USER=root
echo MYSQL_PASSWORD=fmeSFyRCOODoDuPINTxYyzWatYzxxGCt
echo MYSQL_DATABASE=facturacion_medica
echo MYSQL_PORT=10669
echo.
echo # Seguridad
echo SECRET_KEY=a8f5f167f44f4964e6c998dee827110c
echo.
echo # SendGrid ^(Opcional^)
echo SENDGRID_API_KEY=
echo SENDGRID_FROM_EMAIL=noreply@facturacion.com
echo.
echo # Servidor
echo FLASK_ENV=development
echo HOST=0.0.0.0
echo PORT=5000
) > .env

echo.
echo ================================================
echo   ARCHIVO .env CREADO EXITOSAMENTE
echo ================================================
echo.
echo Ubicacion: %CD%\.env
echo.
echo Presiona cualquier tecla para continuar...
pause >nul









