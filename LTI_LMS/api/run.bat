@echo off
REM ============================================================================
REM MTUCI Labs - launcher для Windows
REM ============================================================================
REM Использование:
REM     run.bat              сборка + запуск
REM     run.bat stop         остановить
REM     run.bat logs         смотреть логи
REM     run.bat restart      перезапустить
REM     run.bat rebuild      полная пересборка
REM     run.bat status       статус
REM ============================================================================
setlocal EnableExtensions EnableDelayedExpansion

set IMAGE=mtuci-labs:latest
set CONTAINER=mtuci-labs

REM Управляющие команды
if /i "%~1"=="stop" (
    echo [info] Останавливаю...
    docker compose down 2>nul
    docker stop %CONTAINER% 2>nul
    docker rm %CONTAINER% 2>nul
    exit /b 0
)
if /i "%~1"=="logs" (
    docker logs -f %CONTAINER%
    exit /b 0
)
if /i "%~1"=="restart" (
    docker restart %CONTAINER%
    exit /b 0
)
if /i "%~1"=="status" (
    docker ps -a --filter "name=%CONTAINER%"
    exit /b 0
)
if /i "%~1"=="rebuild" (
    docker compose down 2>nul
    docker stop %CONTAINER% 2>nul
    docker rm %CONTAINER% 2>nul
    docker rmi %IMAGE% 2>nul
)

REM Проверка Docker
where docker >nul 2>&1
if errorlevel 1 (
    echo [err ] Docker не установлен.
    echo.
    echo Скачайте Docker Desktop:
    echo   https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
    echo [err ] Docker daemon не запущен.
    echo Запустите Docker Desktop и дождитесь зелёного индикатора.
    pause
    exit /b 1
)

REM .env
if not exist .env (
    if exist .env.example (
        echo [warn] .env не найден, создаю из .env.example
        copy /Y .env.example .env >nul
        echo.
        echo ВНИМАНИЕ: отредактируйте .env перед production:
        echo   VITE_APP_URL, LTI_PRIVATE_KEY, LAB_FLAG_SECRET и т.д.
        echo.
        set /p YN="Открыть .env в Блокноте? [Y/n] "
        if /i not "!YN!"=="n" notepad .env
    )
)

REM Сборка и запуск через compose, если есть
docker compose version >nul 2>&1
if not errorlevel 1 (
    if exist docker-compose.yml (
        echo [info] Запускаю через docker compose...
        if defined PORT set HTTP_PORT=%PORT%
        docker compose up -d --build
        goto :check
    )
)

REM Fallback: обычный docker
echo [info] Использую обычный docker run...
docker build -t %IMAGE% .
if errorlevel 1 (
    echo [err ] Ошибка сборки.
    pause
    exit /b 1
)

if "%PORT%"=="" set PORT=3000

docker stop %CONTAINER% 2>nul
docker rm %CONTAINER% 2>nul

set ENV_OPT=
if exist .env set ENV_OPT=--env-file .env

docker run -d --name %CONTAINER% -p %PORT%:3000 --restart unless-stopped %ENV_OPT% %IMAGE% >nul
if errorlevel 1 (
    echo [err ] Не удалось запустить контейнер.
    pause
    exit /b 1
)

:check
timeout /t 3 /nobreak >nul

docker ps --format "{{.Names}}" | findstr /B /E "%CONTAINER%" >nul 2>&1
if errorlevel 1 (
    echo [err ] Контейнер не запустился. Логи:
    docker logs %CONTAINER% 2>&1
    pause
    exit /b 1
)

if "%HTTP_PORT%"=="" set HTTP_PORT=%PORT%
if "%HTTP_PORT%"=="" set HTTP_PORT=3000

echo.
echo ============================================================
echo   Готово! Откройте: http://localhost:%HTTP_PORT%
echo ============================================================
echo.
echo   Логи:           run.bat logs
echo   Стоп:           run.bat stop
echo   Перезапуск:     run.bat restart
echo   Пересборка:     run.bat rebuild
echo.

start http://localhost:%HTTP_PORT%

endlocal
