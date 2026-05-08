@echo off
setlocal EnableDelayedExpansion

echo.
echo ================================================
echo   NetWatch - Configuracion inicial de Git
echo ================================================
echo.

git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git no esta instalado: https://git-scm.com
    pause
    exit /b 1
)
echo [OK] Git encontrado.

if not exist "package.json" (
    echo [ERROR] Ejecuta este script desde C:\Projects\netwatch
    pause
    exit /b 1
)
echo [OK] Carpeta correcta.

echo.
echo -- Paso 1: Identidad Git --
echo.
set /p GIT_NAME=Ingresa tu nombre completo: 
set /p GIT_EMAIL=Ingresa tu email de GitHub: 
git config --global user.name "%GIT_NAME%"
git config --global user.email "%GIT_EMAIL%"
echo [OK] Identidad configurada.

echo.
echo -- Paso 2: URL del repositorio GitHub --
echo.
echo Crea el repositorio en GitHub antes de continuar:
echo   1. Ve a https://github.com/new
echo   2. Nombre: netwatch
echo   3. Visibilidad: Private
echo   4. NO marques README ni .gitignore
echo   5. Clic en Create repository
echo   6. Copia la URL (ej: https://github.com/TuUsuario/netwatch.git)
echo.
set /p REPO_URL=Pega aqui la URL del repositorio: 

if "%REPO_URL%"=="" (
    echo [ERROR] URL vacia. Saliendo.
    pause
    exit /b 1
)

echo.
echo -- Paso 3: Inicializando repositorio local --
echo.
if exist ".git" (
    echo [INFO] Repositorio Git ya existe.
) else (
    git init
    echo [OK] Repositorio inicializado.
)

echo.
echo -- Paso 4: Creando primer commit --
echo.
git add .
git commit -m "feat: NetWatch Fase 1"
echo [OK] Commit listo.

echo.
echo -- Paso 5: Conectando con GitHub --
echo.
git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%
git branch -M main
echo [OK] Remote configurado.

echo.
echo -- Paso 6: Subiendo codigo --
echo.
echo GitHub pedira usuario y contrasena.
echo Usa tu Personal Access Token como contrasena.
echo Crealo en: GitHub Settings Developer settings
echo Personal access tokens Tokens classic Generate new token repo
echo.
pause

git push -u origin main
if errorlevel 1 (
    echo [ERROR] Push fallido. Verifica token y URL.
    pause
    exit /b 1
)

echo.
echo ================================================
echo   Listo. Proyecto subido a GitHub.
echo ================================================
echo.
echo Proximos comandos utiles:
echo   git status
echo   git add .
echo   git commit -m "mensaje"
echo   git push
echo.
pause
