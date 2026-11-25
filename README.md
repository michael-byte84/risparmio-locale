# Risparmio - Bilancio Familiare

Applicazione web leggera e 100% locale per la gestione del bilancio familiare, sviluppata in **Python (FastAPI)** con database **SQLite**.

## Caratteristiche principali
- **Gestione Entrate e Uscite:** Tracciamento rapido di movimenti, metodi di pagamento e stati di pagamento.
- **Cicli Carte di Credito:** Calcolo automatico della data di addebito in base al giorno di chiusura estratti conto (cutoff).
- **Spese ed Entrate Ricorrenti:** Pianificazione automatica di rate, abbonamenti e scadenze mensili o annuali.
- **Calcolo Budget e Risparmio:** Suddivisione automatica per obiettivi di accumulo (PAC) e fondo cuscinetto.
- **Privacy e Sicurezza:** Dati salvati esclusivamente in locale (`risparmio.db`), login protetto da password con hash PBKDF2, protezione CSRF e rate-limiting.

## Avvio rapido
- **Linux:** esegui `./avvia_linux.sh`
- **macOS:** esegui `avvia_mac.command`
- **Windows:** esegui `avvia_windows.bat`

Oppure manualmente:

    pip install -r requirements.txt
    uvicorn app:app --reload
