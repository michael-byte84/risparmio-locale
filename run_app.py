import threading
import time
import webbrowser
import uvicorn
from app import app

def apri_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    threading.Thread(target=apri_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
