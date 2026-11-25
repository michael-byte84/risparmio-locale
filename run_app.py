import os
import sys
import socket
import threading
import time
import webbrowser
import uvicorn

# 1. Forza la cartella di lavoro accanto all'eseguibile (.exe) così risparmio.db non viene perso
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

from app import app

def aspetta_e_apri_browser():
    # 2. Attende che il server sia realmente in ascolto (fino a 15 secondi) prima di aprire il browser
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", 8000), timeout=0.5):
                webbrowser.open("http://127.0.0.1:8000")
                return
        except OSError:
            time.sleep(0.5)

if __name__ == "__main__":
    threading.Thread(target=aspetta_e_apri_browser, daemon=True).start()
    # 3. Parametri sicuri per PyInstaller su Windows (niente reload, 1 solo worker)
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False, workers=1)
