# Risparmio - Bilancio Familiare

Applicazione semplice e **100% privata** per gestire entrate, spese e risparmi di casa direttamente sul tuo computer. I tuoi dati non vengono mai inviati online: restano salvati solo sul tuo PC.

---

## Hai Windows e NON hai Python? (Avvio immediato in 3 passaggi)

**Non devi installare nulla.** Puoi scaricare il programma già pronto e avviarlo come qualsiasi normale applicazione di Windows:

1. **Scarica il programma:** clicca su questo link 👉 **[Scarica Risparmio.exe per Windows](../../releases/latest)**, poi scorri in fondo alla pagina fino alla voce **Assets** e clicca su **`Risparmio.exe`**.
2. **Mettilo in una cartella dedicata:** crea una cartella sul tuo PC (ad esempio sul Desktop o in `Documenti` chiamandola `Risparmio`) e sposta lì dentro il file `Risparmio.exe` appena scaricato. *(Importante: il file con tutti i tuoi dati verrà salvato automaticamente in questa stessa cartella).*
3. **Avvialo:** fai **doppio clic** su `Risparmio.exe`. Si aprirà una finestra nera (lasciala aperta finché usi l'app) e dopo pochi secondi si aprirà da sola la schermata del programma nel tuo browser (Chrome, Edge, ecc.).

### ⚠️ Cosa fare se Windows mostra una schermata blu di avviso?
La prima volta che apri il programma, Windows potrebbe mostrare l'avviso *"PC protetto da Windows"* perché è un'app gratuita e indipendente:
1. Clicca sulla scritta **Ulteriori informazioni** (a sinistra).
2. Clicca sul pulsante **Esegui comunque** che appare in basso.

*(Per chiudere l'app quando hai finito, ti basta chiudere la scheda del browser e la finestrella nera).*

---

## Hai un Mac (macOS) senza Python?

Anche su Mac non serve installare Python:

1. Vai alla **[pagina dei download (Releases)](../../releases/latest)** e sotto **Assets** scarica il file chiamato **`Risparmio`** (senza `.exe`).
2. Spostalo in una cartella dedicata e fai **clic con il tasto destro** > **Apri** > conferma **Apri**.
   *(Se al doppio clic si apre come documento di testo invece di avviarsi, apri l'app **Terminale**, scrivi `chmod +x ` con uno spazio finale, trascina il file `Risparmio` dentro il Terminale e premi **Invio**).*

---

## Cosa puoi fare con questa app
* **Entrate e Uscite:** Registra velocemente spese, stipendi, metodi di pagamento e stato (pagato / da pagare).
* **Carte di Credito:** Calcola in automatico il mese di addebito in base al giorno di chiusura dell'estratto conto.
* **Spese Ricorrenti:** Gestisce abbonamenti, rate e bollette mensili o annuali senza doverli reinserire ogni volta.
* **Obiettivi e Risparmio:** Suddivide automaticamente il budget per obiettivi di accumulo (PAC) e fondo emergenze.
* **Backup facilissimo:** Tutti i dati sono salvati in un unico file (`risparmio.db`) nella stessa cartella dell'app: per fare una copia di sicurezza ti basta copiarlo su una chiavetta USB.

---

## Avvio per utenti esperti (con Python già installato)

Se hai già Python installato o usi Linux:

1. Clicca in alto sul pulsante verde **Code** > **Download ZIP** ed estrai la cartella.
2. Avvia lo script per il tuo sistema operativo:
   * **Windows:** doppio clic su `avvia_windows.bat`
   * **macOS:** doppio clic su `avvia_mac.command`
   * **Linux:** esegui `./avvia_linux.sh`

Oppure manualmente da riga di comando (aprendo il **Prompt dei comandi / PowerShell** su Windows, oppure l'app **Terminale** su Mac/Linux dentro la cartella estratta):

    pip install -r requirements.txt
    uvicorn app:app --reload
