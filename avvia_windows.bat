@echo off
setlocal
cd /d "%~dp0"

set "PY_CMD="
py -3 --version >nul 2>nul
if %errorlevel%==0 (
    set "PY_CMD=py -3"
) else (
    python --version >nul 2>nul
    if %errorlevel%==0 (
        set "PY_CMD=python"
    )
)

if "%PY_CMD%"=="" (
    echo Errore: Python 3 non trovato. Scaricalo da https://www.python.org/downloads/
    echo Spunta "Add Python to PATH" durante l'installazione.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creazione ambiente virtuale Python...
    %PY_CMD% -m venv .venv
)

echo Installazione dipendenze...
.venv\Scripts\python.exe -m pip install --upgrade pip -q
.venv\Scripts\python.exe -m pip install -r requirements.txt -q

if not exist ".env" (
    for /f %%i in ('.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"') do set "SECRET=%%i"
    (
        echo DATABASE_URL=sqlite:///./risparmio.db
        echo APP_USER=
        echo APP_PASS=
        echo SESSION_SECRET=%SECRET%
    ) > .env
)

for /f %%p in ('.venv\Scripts\python.exe -c "import socket; print(next(p for p in range(8090,8190) if socket.socket().connect_ex((\"127.0.0.1\",p))!=0))"') do set "PORTA=%%p"

echo Avvio su http://127.0.0.1:%PORTA% ...
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:%PORTA%"
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port %PORTA%
pause
