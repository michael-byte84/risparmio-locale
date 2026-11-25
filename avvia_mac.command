#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Errore: Python 3 non trovato. Scaricalo da https://www.python.org/downloads/macos/"
  read -p "Premi Invio per uscire..."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creazione ambiente virtuale Python..."
  python3 -m venv .venv
fi

echo "Installazione dipendenze..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt -q

if [ ! -f ".env" ]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cat << EOT > .env
DATABASE_URL=sqlite:///./risparmio.db
APP_USER=
APP_PASS=
SESSION_SECRET=$SECRET
EOT
fi

PORTA=$(python3 -c "
import socket
for p in range(8090, 8190):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', p)) != 0:
            print(p)
            break
")

echo "Avvio su http://127.0.0.1:$PORTA ..."
(sleep 2 && open "http://127.0.0.1:$PORTA" || true) &
.venv/bin/uvicorn app:app --host 127.0.0.1 --port "$PORTA"
