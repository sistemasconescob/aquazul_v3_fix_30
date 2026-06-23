@echo off
setlocal enabledelayedexpansion
title Aquazul Piscinas Sanas
color 0A
echo.
echo  ==========================================
echo    AQUAZUL PISCINAS SANAS v3.0
echo  ==========================================
echo.

:: Verificar Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python no esta instalado.
    echo.
    echo  Descarga Python desde:
    echo  https://www.python.org/downloads/
    echo.
    echo  IMPORTANTE: Marca la casilla
    echo  "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

:: Ir a la raiz del proyecto
cd /d "%~dp0"

:: Cargar variables del .env si existe
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "linea=%%A"
        if not "!linea:~0,1!"=="#" (
            if not "%%A"=="" (
                set "%%A=%%B"
            )
        )
    )
    echo  .env cargado OK
) else (
    echo  AVISO: no se encontro .env, usando valores por defecto
)

echo.
echo  Servidor iniciando...
echo.
echo  Abre en tu navegador:
echo  http://localhost:8000
echo.
echo  Credenciales:
echo  Email:      admin@aquazul.co
echo  Contrasena: Admin2024*
echo.
echo  Presiona Ctrl+C para detener
echo  ==========================================
echo.

cd backend
python server.py
echo.
echo  El servidor se detuvo.
pause
