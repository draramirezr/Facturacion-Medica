@echo off
echo ================================================
echo   CREANDO ARCHIVO DE CONFIGURACION .env
echo ================================================
echo.

(
echo # Configuracion MySQL - Railway
echo MYSQL_URL=CAMBIAR_AQUI
echo.
echo # Configuracion Separada
echo MYSQL_HOST=CAMBIAR_AQUI
echo MYSQL_USER=CAMBIAR_AQUI
echo MYSQL_PASSWORD=CAMBIAR_AQUI
echo MYSQL_DATABASE=CAMBIAR_AQUI
echo MYSQL_PORT=CAMBIAR_AQUI
echo.
echo # Seguridad
echo SECRET_KEY=CAMBIAR_AQUI
echo.
echo # Zoho — correo de ClinicRD
echo ZOHO_SMTP_HOST=smtp.zoho.com
echo ZOHO_SMTP_PORT=587
echo ZOHO_SMTP_USER=CAMBIAR_AQUI
echo ZOHO_SMTP_PASSWORD=CAMBIAR_AQUI
echo ZOHO_FROM_EMAIL=CAMBIAR_AQUI
echo ZOHO_FROM_NAME=ClinicRD
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









