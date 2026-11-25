"""
Risparmio Backend - Bilancio familiare a cicli 23 -> 22.

Applicazione FastAPI con database SQLite (./risparmio.db).
La logica di calcolo del budget e del risparmio arriva da budget_core.py.
"""

from __future__ import annotations

import calendar
import csv
import html
import io
import json
import os
import re
import secrets
import time
import hmac
import hashlib
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo
from typing import Generator, Optional
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    Float,
    Integer,
    String,
    create_engine,
    func,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from budget_core import calcola_budget, calcola_data_addebito_cc

# ---------------------------------------------------------------------------
# Configurazione & Caricamento .env
# ---------------------------------------------------------------------------


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except OSError:
        pass


_load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./risparmio.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

GIORNO_INIZIO_CICLO = 1
DATA_INIZIO_CONTABILITA = date.today().replace(day=1)
TIPO_IMMEDIATO = "pagamento immediato"

METODI_BASE = ["Bancomat", "Bonifico", "SDD", "Contanti", "Da valutare"]
CARTE_DEFAULT = [
    {"nome": "Visa", "cutoff": 2, "addebito": 12},
    {"nome": "AmEx", "cutoff": 16, "addebito": 0},
]
METODI = [c["nome"] for c in CARTE_DEFAULT] + METODI_BASE

MESI = [
    "gen", "feb", "mar", "apr", "mag", "giu",
    "lug", "ago", "set", "ott", "nov", "dic",
]
GIORNI = ["lun", "mar", "mer", "gio", "ven", "sab", "dom"]

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()

app = FastAPI(title="Risparmio - Bilancio familiare", docs_url=None, redoc_url=None, openapi_url=None)

COOKIE_NAME = "risparmio_session"
SESSION_MAX_AGE = 30 * 24 * 60 * 60  # 30 giorni
_RUNTIME_FALLBACK_SECRET = secrets.token_hex(32)
_LOGIN_FAILURES: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SEC = 300



def _hash_password(password: str, salt_hex: Optional[str] = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{salt.hex()}:{dk.hex()}"


def _verify_password_hash(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, dk_hex = stored_hash.split(":", 1)
        check = _hash_password(password, salt_hex)
        return secrets.compare_digest(check, stored_hash)
    except Exception:
        return False


def _get_auth_credentials() -> tuple[str, str]:
    """Restituisce (username, password_hash_o_secret) dal DB oppure da .env se presenti."""
    try:
        with SessionLocal() as db:
            u_row = db.get(Config, "auth_user")
            p_row = db.get(Config, "auth_pass_hash")
            if u_row and u_row.valore and p_row and p_row.valore:
                return u_row.valore.strip(), p_row.valore.strip()
    except Exception:
        pass
    env_u = os.getenv("APP_USER", "").strip()
    env_p = os.getenv("APP_PASS", "").strip()
    if env_u and env_p:
        return env_u, f"ENV:{env_p}"
    return "", ""

def _get_session_secret(expected_pass: str) -> bytes:
    secret = os.getenv("SESSION_SECRET") or expected_pass or _RUNTIME_FALLBACK_SECRET
    return secret.encode("utf-8")


def _sign_session(user: str, pwd: str) -> str:
    exp = str(int(time.time()) + SESSION_MAX_AGE)
    nonce = secrets.token_hex(8)
    payload = f"{user}:{exp}:{nonce}"
    sig = hmac.new(_get_session_secret(pwd), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_session(cookie_val: str, expected_user: str, expected_pass: str) -> bool:
    try:
        user, exp_str, nonce, sig = cookie_val.rsplit(":", 3)
        if int(exp_str) < int(time.time()):
            return False
        if not secrets.compare_digest(user, expected_user):
            return False
        payload = f"{user}:{exp_str}:{nonce}"
        expected_sig = hmac.new(_get_session_secret(expected_pass), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return secrets.compare_digest(sig, expected_sig)
    except Exception:
        return False


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _LOGIN_FAILURES.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    _LOGIN_FAILURES[ip] = recent
    return len(recent) >= _LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip: str) -> None:
    now = time.time()
    recent = [t for t in _LOGIN_FAILURES.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    recent.append(now)
    _LOGIN_FAILURES[ip] = recent


def _is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.lower() == "https"


def _render_login_page(errore: bool = False) -> str:
    err_html = '<p style="color:#dc2626;font-size:14px;margin:0 0 14px;">Credenziali non valide</p>' if errore else ""
    return f"""<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accedi - Risparmio</title>
  <style>
    body {{ font-family:system-ui,-apple-system,sans-serif; background: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 16px; }}
    .card {{ background: #fff; padding: 28px; border-radius: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.08); width: 100%; max-width: 340px; }}
    h1 {{ font-size: 20px; margin: 0 0 18px; color: #111827; text-align: center; }}
    label {{ display: block; font-size: 13px; color: #374151; margin-bottom: 4px; font-weight: 500; }}
    input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; margin-bottom: 14px; font-size: 15px; }}
    button {{ width: 100%; padding: 11px; background: #111827; color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }}
    button:hover {{ background: #1f2937; }}
  </style>







<style>
@media(max-width: 600px) {{
  .mov-row {{
    display: flex !important;
    flex-direction: column !important;
    align-items: flex-start !important;
    padding: 16px 12px !important;
    gap: 12px !important;
    border-bottom: 1px solid var(--border) !important;
    height: auto !important;
    position: static !important;
  }}
  
  .mov-date, .mov-meta, .mov-title .badge {{ display: none !important; }}
  
  .mov-main, .mov-right, .mov-amount {{
    display: block !important;
    width: 100% !important;
    margin: 0 !important;
    padding: 0 !important;
    text-align: left !important;
    line-height: 1.4 !important;
  }}
  
  /* Riga 1: Titolo (NO GRASSETTO) */
  .mov-title {{
    font-size: 1.1rem !important;
    font-weight: normal !important; 
    white-space: normal !important;
  }}
  
  /* Riga 2: Cifra (NO GRASSETTO) */
  .mov-amount {{
    font-size: 1.2rem !important;
    font-weight: normal !important;
  }}
  
  /* Riga 3: Comandi */
  .mov-actions {{
    display: flex !important;
    flex-direction: row !important;
    justify-content: flex-start !important;
    align-items: center !important;
    gap: 12px !important;
    width: 100% !important;
    margin-top: 4px !important;
  }}
  
  .mov-actions form, .mov-actions button, .mov-actions .btn {{
    height: 44px !important;
    width: 44px !important;
    min-width: 44px !important;
    font-size: 1.2rem !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    border-radius: 8px !important;
  }}
}}
</style>
</head>

<body>
  <div class="card">
    <h1>Risparmio</h1>
    {err_html}
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="username" required autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Accedi (ricorda per 30 giorni)</button>
    </form>
  </div>
</body>
</html>"""


def _render_setup_account_page(errore: str = "") -> str:
    err_html = f'<div class="err">{esc(errore)}</div>' if errore else ""
    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Benvenuto · Crea il tuo account</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#f1f5f9; color:#0f172a; display:grid; place-items:center; min-height:100vh; margin:0; padding:16px; }}
  .card {{ background:#fff; border:1px solid #e2e8f0; border-radius:16px; padding:28px; width:100%; max-width:420px; box-shadow:0 12px 30px rgba(15,23,42,.08); }}
  h1 {{ margin:0 0 6px; font-size:1.45rem; }}
  p.sub {{ margin:0 0 20px; color:#64748b; font-size:.92rem; line-height:1.45; }}
  label {{ display:block; font-size:.86rem; font-weight:600; margin-bottom:6px; }}
  input {{ width:100%; box-sizing:border-box; padding:11px 12px; border:1px solid #cbd5e1; border-radius:10px; font-size:1rem; margin-bottom:14px; }}
  button {{ width:100%; padding:12px; border:0; border-radius:10px; background:#2563eb; color:#fff; font-weight:700; font-size:1rem; cursor:pointer; }}
  button:hover {{ background:#1d4ed8; }}
  .err {{ background:#fef2f2; color:#b91c1c; border:1px solid #fecaca; padding:10px 12px; border-radius:10px; font-size:.88rem; margin-bottom:14px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>👋 Benvenuto in Risparmio</h1>
    <p class="sub">Crea il tuo <strong>nome utente</strong> e la tua <strong>password</strong> locali per proteggere i tuoi dati finanziari.</p>
    {err_html}
    <form method="post" action="/setup-account">
      <label for="username">Scegli un Nome Utente</label>
      <input id="username" name="username" type="text" minlength="3" maxlength="50" autocomplete="username" placeholder="Es. marco" required autofocus>
      <label for="password">Scegli una Password (min. 4 caratteri)</label>
      <input id="password" name="password" type="password" minlength="4" maxlength="100" autocomplete="new-password" required>
      <label for="password_confirm">Conferma Password</label>
      <input id="password_confirm" name="password_confirm" type="password" minlength="4" maxlength="100" autocomplete="new-password" required>
      <button type="submit">Crea account e inizia →</button>
    </form>
  </div>
</body>
</html>"""


@app.get("/setup-account", response_class=HTMLResponse)
def setup_account_page():
    u, p = _get_auth_credentials()
    if u and p:
        return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse(_render_setup_account_page())


@app.post("/setup-account")
def setup_account_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    u_curr, p_curr = _get_auth_credentials()
    if u_curr and p_curr:
        return RedirectResponse(url="/login", status_code=303)
    u_clean = username.strip()
    if len(u_clean) < 3:
        return HTMLResponse(_render_setup_account_page("Il nome utente deve avere almeno 3 caratteri."), status_code=400)
    if len(password) < 4:
        return HTMLResponse(_render_setup_account_page("La password deve avere almeno 4 caratteri."), status_code=400)
    if password != password_confirm:
        return HTMLResponse(_render_setup_account_page("Le due password non coincidono."), status_code=400)

    p_hash = _hash_password(password)
    with SessionLocal() as db:
        for k, v in (("auth_user", u_clean), ("auth_pass_hash", p_hash)):
            row = db.get(Config, k)
            if row is None:
                db.add(Config(chiave=k, valore=v))
            else:
                row.valore = v
        db.commit()

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=_sign_session(u_clean, p_hash),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=_is_https(request),
    )
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page():
    u, p = _get_auth_credentials()
    if not u or not p:
        return RedirectResponse(url="/setup-account", status_code=303)
    return HTMLResponse(_render_login_page())


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = _client_ip(request)
    if _is_rate_limited(ip):
        return HTMLResponse(
            _render_login_page(errore=True).replace("Credenziali non valide", "Troppi tentativi falliti. Riprova tra 5 minuti."),
            status_code=429,
        )
    expected_user, stored_secret = _get_auth_credentials()
    if not expected_user or not stored_secret:
        return RedirectResponse(url="/setup-account", status_code=303)

    ok_user = secrets.compare_digest(username.strip(), expected_user)
    if stored_secret.startswith("ENV:"):
        ok_pass = secrets.compare_digest(password, stored_secret[4:])
    else:
        ok_pass = _verify_password_hash(password, stored_secret)

    if ok_user and ok_pass:
        _LOGIN_FAILURES.pop(ip, None)
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie(
            key=COOKIE_NAME,
            value=_sign_session(expected_user, stored_secret),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=_is_https(request),
        )
        return resp
    _record_login_failure(ip)
    return HTMLResponse(_render_login_page(errore=True), status_code=401)


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME, httponly=True, samesite="strict")
    return resp


@app.middleware("http")
async def session_auth_middleware(request: Request, call_next):
    expected_user, stored_secret = _get_auth_credentials()
    is_test_env = "PYTEST_CURRENT_TEST" in os.environ

    _PUBLIC_ASSET_PATHS = {
        "/login",
        "/setup-account",
        "/icon.svg",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/favicon.ico",
        "/icon-192.png?v=2",
        "/icon-512.png?v=2",
        "/manifest.webmanifest",
    }

    if not is_test_env and (not expected_user or not stored_secret):
        if request.url.path not in _PUBLIC_ASSET_PATHS:
            return RedirectResponse(url="/setup-account", status_code=303)

    if expected_user and stored_secret and request.url.path not in _PUBLIC_ASSET_PATHS:
        token = request.cookies.get(COOKIE_NAME, "")
        if not _verify_session(token, expected_user, stored_secret):
            return RedirectResponse(url="/login", status_code=303)

    # Protezione CSRF Same-Origin sulle richieste mutanti
    if request.method in ("POST", "PUT", "DELETE"):
        from urllib.parse import urlparse
        allowed_hosts = set()
        for h_hdr in (request.headers.get("host", ""), request.headers.get("x-forwarded-host", "")):
            for part in h_hdr.split(","):
                clean_h = part.strip().split(":")[0].lower()
                if clean_h:
                    allowed_hosts.add(clean_h)
        sorgente = request.headers.get("origin") or request.headers.get("referer") or ""
        if sorgente:
            src_host = (urlparse(sorgente).hostname or "").lower()
            is_local_upstream = allowed_hosts <= {"127.0.0.1", "localhost", "::1"}
            if src_host and allowed_hosts and not is_local_upstream and src_host not in allowed_hosts:
                return Response("Richiesta cross-origin non consentita (CSRF)", status_code=403)

    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response



os.environ["TZ"] = "Europe/Rome"
if hasattr(time, "tzset"):
    time.tzset()

_TZ_ITALIA = ZoneInfo("Europe/Rome")
_OFFSET_SERVER_SEC: float = 0.0
_ULTIMO_SYNC_ORA: float = 0.0


def _sincronizza_offset_rete() -> None:
    """Sincronizza eventuale scarto con i server Google (cache 6 ore)."""
    global _OFFSET_SERVER_SEC, _ULTIMO_SYNC_ORA
    now_mono = time.monotonic()
    if _ULTIMO_SYNC_ORA and (now_mono - _ULTIMO_SYNC_ORA) < 21600:
        return
    _ULTIMO_SYNC_ORA = now_mono
    for url in ("https://www.google.com/generate_204", "https://1.1.1.1"):
        try:
            with httpx.Client(timeout=1.5) as client:
                r = client.head(url)
            date_hdr = r.headers.get("date")
            if date_hdr:
                dt_rete = parsedate_to_datetime(date_hdr)
                dt_locale = datetime.now(dt_rete.tzinfo)
                _OFFSET_SERVER_SEC = (dt_rete - dt_locale).total_seconds()
                return
        except Exception:
            continue


def adesso_italia() -> datetime:
    """Restituisce data e ora esatte in Italia (Europe/Rome) sincronizzate."""
    _sincronizza_offset_rete()
    adesso_utc = datetime.now(ZoneInfo("UTC")) + timedelta(seconds=_OFFSET_SERVER_SEC)
    return adesso_utc.astimezone(_TZ_ITALIA)


def oggi_italia() -> date:
    """Restituisce la data odierna reale in Italia (Europe/Rome)."""
    return adesso_italia().date()


# ---------------------------------------------------------------------------
# Modelli
# ---------------------------------------------------------------------------


class Entrata(Base):
    __tablename__ = "entrate"

    id = Column(Integer, primary_key=True, index=True)
    descrizione = Column(String, nullable=False)
    importo = Column(Float, nullable=False, default=0.0)
    data = Column(Date, nullable=False, index=True)
    provenienza = Column(String, nullable=True, default="")


class Spesa(Base):
    __tablename__ = "spese"

    id = Column(Integer, primary_key=True, index=True)
    data = Column(Date, nullable=False, index=True)
    data_acquisto = Column(Date, nullable=True)
    descrizione = Column(String, nullable=False)
    importo = Column(Float, nullable=False, default=0.0)
    metodo = Column(String, nullable=False, default="Contanti")
    tipo = Column(String, nullable=False, default=TIPO_IMMEDIATO)
    pagata = Column(Boolean, nullable=False, default=False)


class Config(Base):
    __tablename__ = "config"

    chiave = Column(String, primary_key=True)
    valore = Column(String, nullable=False, default="")


class Ricorrenza(Base):
    __tablename__ = "ricorrenze"

    id = Column(Integer, primary_key=True, index=True)
    categoria = Column(String, nullable=False, default="spesa")
    frequenza = Column(String, nullable=False, default="mensile")
    descrizione = Column(String, nullable=False)
    importo = Column(Float, nullable=False, default=0.0)
    giorno_scadenza = Column(Integer, nullable=False, default=1)
    mese_scadenza = Column(Integer, nullable=True)
    metodo = Column(String, nullable=False, default="Contanti")
    provenienza = Column(String, nullable=False, default="")
    tipo_spesa = Column(String, nullable=False, default="fissa")
    data_inizio = Column(Date, nullable=False)
    data_fine = Column(Date, nullable=True)
    num_rate = Column(Integer, nullable=True)
    pagata = Column(Boolean, nullable=False, default=False)
    attiva = Column(Boolean, nullable=False, default=True)


def _data_sicura(anno: int, mese: int, giorno: int) -> date:
    ultimo = calendar.monthrange(anno, mese)[1]
    return date(anno, mese, min(max(1, giorno), ultimo))


def _aggiungi_mesi(d: date, mesi: int) -> date:
    tot_mesi = (d.year * 12 + (d.month - 1)) + mesi
    anno = tot_mesi // 12
    mese = (tot_mesi % 12) + 1
    return _data_sicura(anno, mese, d.day)


def _calcola_data_fine_ricorrenza(
    data_inizio: date,
    frequenza: str,
    giorno_scadenza: int,
    mese_scadenza: Optional[int],
    num_rate: Optional[int],
    data_fine: Optional[date],
) -> Optional[date]:
    if data_fine:
        return data_fine
    if num_rate and num_rate > 0:
        if frequenza == "annuale":
            mese_t = mese_scadenza or data_inizio.month
            primo = _data_sicura(data_inizio.year, mese_t, giorno_scadenza)
            anno_start = data_inizio.year if primo >= data_inizio else data_inizio.year + 1
            return _data_sicura(anno_start + num_rate - 1, mese_t, giorno_scadenza)
        else:
            primo = _data_sicura(data_inizio.year, data_inizio.month, giorno_scadenza)
            offset = 0 if primo >= data_inizio else 1
            base = _aggiungi_mesi(date(data_inizio.year, data_inizio.month, 1), offset + num_rate - 1)
            return _data_sicura(base.year, base.month, giorno_scadenza)
    return None


def _orizzonte_massimo_db(db: Session, oggi: date) -> date:
    """Restituisce l'ultima data coperta da rate/ricorrenze o movimenti nel DB (almeno fine ciclo corrente)."""
    limite = fine_ciclo(inizio_ciclo(oggi))
    max_spesa = db.query(func.max(Spesa.data)).scalar()
    if max_spesa and max_spesa > limite:
        limite = fine_ciclo(inizio_ciclo(max_spesa))
    max_entrata = db.query(func.max(Entrata.data)).scalar()
    if max_entrata and max_entrata > limite:
        limite = fine_ciclo(inizio_ciclo(max_entrata))
    regole = db.query(Ricorrenza).filter(Ricorrenza.attiva.is_(True)).all()
    for r in regole:
        df = _calcola_data_fine_ricorrenza(
            r.data_inizio, r.frequenza, r.giorno_scadenza, r.mese_scadenza, r.num_rate, r.data_fine
        )
        if df:
            effettiva = calcola_addebito_carta(r.metodo or "Contanti", df) if (r.categoria != "entrata" and is_carta_credito(r.metodo)) else df
            if effettiva > limite:
                limite = fine_ciclo(inizio_ciclo(effettiva))
    min_orizzonte = fine_ciclo(inizio_ciclo(_aggiungi_mesi(oggi, 12)))
    if min_orizzonte > limite:
        limite = min_orizzonte
    return limite


def sincronizza_ricorrenze(db: Session, fino_a: Optional[date] = None) -> None:
    """Materializza le ricorrenze fino all'ultima rata impostata (o fino_a se specificato)."""
    oggi = oggi_italia()
    regole = db.query(Ricorrenza).filter(Ricorrenza.attiva.is_(True)).all()
    if not regole:
        return

    orizzonte_globale = _orizzonte_massimo_db(db, oggi)
    if fino_a and fino_a > orizzonte_globale:
        orizzonte_globale = fine_ciclo(inizio_ciclo(fino_a))

    entrate_esistenti = {
        (e.data, (e.descrizione or "").strip().lower())
        for e in db.query(Entrata.data, Entrata.descrizione)
        .filter(Entrata.data >= DATA_INIZIO_CONTABILITA, Entrata.data <= orizzonte_globale)
        .all()
    }
    spese_esistenti = {
        (s.data, (s.descrizione or "").strip().lower(), (s.metodo or "").strip())
        for s in db.query(Spesa.data, Spesa.descrizione, Spesa.metodo)
        .filter(Spesa.data >= DATA_INIZIO_CONTABILITA, Spesa.data <= orizzonte_globale)
        .all()
    }

    nuovi_oggetti = []
    for r in regole:
        fine_regola = _calcola_data_fine_ricorrenza(
            r.data_inizio, r.frequenza, r.giorno_scadenza, r.mese_scadenza, r.num_rate, r.data_fine
        )
        limite_regola = fine_regola if fine_regola else orizzonte_globale

        if r.frequenza == "annuale":
            mese_target = r.mese_scadenza or r.data_inizio.month
            anno_max = limite_regola.year
            for anno in range(r.data_inizio.year, anno_max + 1):
                occ = _data_sicura(anno, mese_target, r.giorno_scadenza)
                if occ < r.data_inizio or occ > limite_regola:
                    continue
                if r.categoria == "entrata":
                    chiave = (occ, (r.descrizione or "").strip().lower())
                    if chiave not in entrate_esistenti:
                        entrate_esistenti.add(chiave)
                        nuovi_oggetti.append(Entrata(
                            descrizione=r.descrizione,
                            importo=r.importo,
                            data=occ,
                            provenienza=r.provenienza or "",
                        ))
                else:
                    met_ric = r.metodo or "Contanti"
                    data_add = calcola_addebito_carta(met_ric, occ) if is_carta_credito(met_ric) else occ
                    data_acq = occ if is_carta_credito(met_ric) else None
                    chiave = (data_add, (r.descrizione or "").strip().lower(), met_ric.strip())
                    if chiave not in spese_esistenti:
                        spese_esistenti.add(chiave)
                        nuovi_oggetti.append(Spesa(
                            data=data_add,
                            data_acquisto=data_acq,
                            descrizione=r.descrizione,
                            importo=r.importo,
                            metodo=met_ric,
                            tipo=r.tipo_spesa or "fissa",
                            pagata=False if met_ric == "Da valutare" else bool(is_carta_credito(met_ric) or getattr(r, "pagata", False)),
                        ))
        else:
            idx = 0
            while True:
                base = _aggiungi_mesi(date(r.data_inizio.year, r.data_inizio.month, 1), idx)
                occ = _data_sicura(base.year, base.month, r.giorno_scadenza)
                idx += 1
                if occ < r.data_inizio:
                    continue
                if occ > limite_regola:
                    break
                if r.categoria == "entrata":
                    chiave = (occ, (r.descrizione or "").strip().lower())
                    if chiave not in entrate_esistenti:
                        entrate_esistenti.add(chiave)
                        nuovi_oggetti.append(Entrata(
                            descrizione=r.descrizione,
                            importo=r.importo,
                            data=occ,
                            provenienza=r.provenienza or "",
                        ))
                else:
                    met_ric = r.metodo or "Contanti"
                    data_add = calcola_addebito_carta(met_ric, occ) if is_carta_credito(met_ric) else occ
                    data_acq = occ if is_carta_credito(met_ric) else None
                    chiave = (data_add, (r.descrizione or "").strip().lower(), met_ric.strip())
                    if chiave not in spese_esistenti:
                        spese_esistenti.add(chiave)
                        nuovi_oggetti.append(Spesa(
                            data=data_add,
                            data_acquisto=data_acq,
                            descrizione=r.descrizione,
                            importo=r.importo,
                            metodo=met_ric,
                            tipo=r.tipo_spesa or "fissa",
                            pagata=False if met_ric == "Da valutare" else bool(is_carta_credito(met_ric) or getattr(r, "pagata", False)),
                        ))

    carte_da_allineare = (
        db.query(Spesa)
        .filter(Spesa.metodo.in_(list(CARTE_ATTIVE_MAP.keys())))
        .all()
    )
    modificate = False
    for sc in carte_da_allineare:
        if not sc.pagata:
            sc.pagata = True
            modificate = True
        if sc.data_acquisto:
            nuova_d = calcola_addebito_carta(sc.metodo, sc.data_acquisto)
            if sc.data != nuova_d:
                sc.data = nuova_d
                modificate = True
    if nuovi_oggetti:
        db.add_all(nuovi_oggetti)
    if nuovi_oggetti or modificate:
        db.commit()


def init_db() -> None:
    """Crea le tabelle e i valori di configurazione iniziali."""
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    if "ricorrenze" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("ricorrenze")}
        if "num_rate" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE ricorrenze ADD COLUMN num_rate INTEGER"))
        if "pagata" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE ricorrenze ADD COLUMN pagata BOOLEAN NOT NULL DEFAULT FALSE"))
    with SessionLocal() as db:
        oggi_def = date.today()
        default_start = date(oggi_def.year, oggi_def.month, 1).isoformat()
        for chiave, valore in (
            ("pac_percentuale", "0.10"),
            ("cuscinetto_percentuale", "0.0"),
            ("pac_fisso", "0.0"),
            ("cuscinetto_fisso", "0.0"),
            ("giorno_inizio_ciclo", "1"),
            ("data_inizio_contabilita", default_start),
            ("carte_credito_json", json.dumps(CARTE_DEFAULT, ensure_ascii=False)),
            ("wizard_completato", "0"),
        ):
            if db.get(Config, chiave) is None:
                db.add(Config(chiave=chiave, valore=valore))
        db.commit()
    ricarica_impostazioni_globali()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



CARTE_ATTIVE_MAP: dict[str, dict] = {c["nome"]: c for c in CARTE_DEFAULT}


def ricarica_impostazioni_globali(db: Optional[Session] = None) -> dict:
    global GIORNO_INIZIO_CICLO, DATA_INIZIO_CONTABILITA, METODI, CARTE_ATTIVE_MAP
    chiudi = False
    if db is None:
        db = SessionLocal()
        chiudi = True
    try:
        def _g(k: str, d: str) -> str:
            row = db.get(Config, k)
            return row.valore if (row and row.valore is not None) else d

        try:
            g = int(_g("giorno_inizio_ciclo", "1"))
            GIORNO_INIZIO_CICLO = min(28, max(1, g))
        except ValueError:
            GIORNO_INIZIO_CICLO = 1

        raw_start = _g("data_inizio_contabilita", "")
        try:
            DATA_INIZIO_CONTABILITA = date.fromisoformat(raw_start[:10])
        except ValueError:
            oggi_loc = date.today()
            if oggi_loc.day >= GIORNO_INIZIO_CICLO:
                DATA_INIZIO_CONTABILITA = date(oggi_loc.year, oggi_loc.month, GIORNO_INIZIO_CICLO)
            elif oggi_loc.month == 1:
                DATA_INIZIO_CONTABILITA = date(oggi_loc.year - 1, 12, GIORNO_INIZIO_CICLO)
            else:
                DATA_INIZIO_CONTABILITA = date(oggi_loc.year, oggi_loc.month - 1, GIORNO_INIZIO_CICLO)

        try:
            carte_list = json.loads(_g("carte_credito_json", "[]"))
            if not isinstance(carte_list, list):
                carte_list = []
        except Exception:
            carte_list = []

        carte_pulite = []
        visti = set()
        for c in carte_list:
            if not isinstance(c, dict):
                continue
            nome = str(c.get("nome", "")).strip()
            if not nome or nome in visti or nome in METODI_BASE:
                continue
            visti.add(nome)
            cutoff = min(28, max(1, int(c.get("cutoff", 15))))
            addebito = min(28, max(0, int(c.get("addebito", 0))))
            carte_pulite.append({"nome": nome, "cutoff": cutoff, "addebito": addebito})

        CARTE_ATTIVE_MAP = {c["nome"]: c for c in carte_pulite}
        METODI = [c["nome"] for c in carte_pulite] + METODI_BASE
        wizard_done = _g("wizard_completato", "0") == "1"
        auth_u, _ = _get_auth_credentials()
        return {
            "giorno_inizio_ciclo": GIORNO_INIZIO_CICLO,
            "data_inizio_contabilita": DATA_INIZIO_CONTABILITA.isoformat(),
            "carte": carte_pulite,
            "wizard_completato": wizard_done,
            "auth_user": auth_u,
        }
    finally:
        if chiudi:
            db.close()


def is_carta_credito(metodo: Optional[str]) -> bool:
    return bool(metodo and metodo in CARTE_ATTIVE_MAP)


def calcola_addebito_carta(metodo: str, data_acquisto: date) -> date:
    return calcola_data_addebito_cc(metodo, data_acquisto, CARTE_ATTIVE_MAP)

init_db()


# ---------------------------------------------------------------------------
# Helper sui cicli (23 del mese -> 22 del mese successivo)
# ---------------------------------------------------------------------------


def inizio_ciclo(giorno: date) -> date:
    if giorno.day >= GIORNO_INIZIO_CICLO:
        return date(giorno.year, giorno.month, GIORNO_INIZIO_CICLO)
    if giorno.month == 1:
        return date(giorno.year - 1, 12, GIORNO_INIZIO_CICLO)
    return date(giorno.year, giorno.month - 1, GIORNO_INIZIO_CICLO)


def fine_ciclo(inizio: date) -> date:
    if inizio.month == 12:
        prossimo = date(inizio.year + 1, 1, GIORNO_INIZIO_CICLO)
    else:
        prossimo = date(inizio.year, inizio.month + 1, GIORNO_INIZIO_CICLO)
    return prossimo - timedelta(days=1)


def chiave_ciclo(inizio: date) -> str:
    return inizio.strftime("%Y-%m")


def etichetta_ciclo(inizio: date) -> str:
    fine = fine_ciclo(inizio)
    return f"{MESI[inizio.month - 1]}-{MESI[fine.month - 1]} {fine.year}"


def parse_chiave_ciclo(valore: Optional[str]) -> Optional[date]:
    if not valore:
        return None
    try:
        anno_s, mese_s = valore.split("-", 1)
        anno, mese = int(anno_s), int(mese_s)
        if 1900 <= anno <= 2200 and 1 <= mese <= 12:
            return date(anno, mese, GIORNO_INIZIO_CICLO)
    except (ValueError, AttributeError):
        pass
    return None


def elenco_cicli(db: Optional[Session] = None) -> list[date]:
    primo = inizio_ciclo(DATA_INIZIO_CONTABILITA)
    if db is not None:
        ultimo = inizio_ciclo(_orizzonte_massimo_db(db, oggi_italia()))
    else:
        ultimo = inizio_ciclo(oggi_italia())
    if ultimo < primo:
        ultimo = primo
    cicli: list[date] = []
    corrente = primo
    while corrente <= ultimo:
        cicli.append(corrente)
        corrente = fine_ciclo(corrente) + timedelta(days=1)
    return cicli


# ---------------------------------------------------------------------------
# Helper di parsing e formattazione
# ---------------------------------------------------------------------------


def parse_date(valore: Optional[str], default: Optional[date] = None) -> Optional[date]:
    if not valore:
        return default
    testo = str(valore).strip()[:10]
    try:
        return date.fromisoformat(testo)
    except ValueError:
        try:
            g, m, a = testo.split("/")
            return date(int(a), int(m), int(g))
        except (ValueError, TypeError):
            return default


def parse_importo(valore: Optional[str]) -> float:
    if valore is None:
        return 0.0
    testo = str(valore).strip().replace("€", "").replace(" ", "").replace("\u00a0", "")
    if not testo:
        return 0.0
    if "," in testo and "." in testo:
        if testo.rfind(",") > testo.rfind("."):
            testo = testo.replace(".", "").replace(",", ".")
        else:
            testo = testo.replace(",", "")
    elif "," in testo:
        testo = testo.replace(",", ".")
    try:
        return round(float(testo), 2)
    except ValueError:
        return 0.0


def esc(valore: object) -> str:
    return html.escape("" if valore is None else str(valore), quote=True)


def json_attr(valore: dict) -> str:
    return esc(json.dumps(valore, ensure_ascii=False))


def fmt_money(valore: float, segno: bool = False) -> str:
    numero = float(valore or 0)
    negativo = numero < 0
    corpo = f"{abs(numero):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    if negativo:
        prefisso = "-€ "
    elif segno and numero > 0:
        prefisso = "+€ "
    else:
        prefisso = "€ "
    return f"{prefisso}{corpo}"


def fmt_input(valore: float) -> str:
    return f"{float(valore or 0):.2f}"


def data_breve(giorno: date) -> str:
    return giorno.strftime("%d/%m")


def data_italiana(giorno: date) -> str:
    return giorno.strftime("%d/%m/%Y")


def nome_giorno(giorno: date) -> str:
    return GIORNI[giorno.weekday()]


def config_float(db: Session, chiave: str, default: float) -> float:
    voce = db.get(Config, chiave)
    if voce is None:
        return default
    try:
        return float(str(voce.valore).replace(",", "."))
    except ValueError:
        return default


def metodo_options(selezionato: Optional[str] = None) -> str:
    return "".join(
        f'<option value="{esc(metodo)}"'
        f'{" selected" if metodo == selezionato else ""}>{esc(metodo)}</option>'
        for metodo in METODI
    )


def tipo_options(selezionato: Optional[str] = None) -> str:
    opzioni = [
        (TIPO_IMMEDIATO, "Variabile / immediata"),
        ("fissa", "Spesa ricorrente"),
    ]
    return "".join(
        f'<option value="{esc(valore)}"'
        f'{" selected" if valore == selezionato else ""}>{esc(label)}</option>'
        for valore, label in opzioni
    )


def hidden_vista(ciclo_key: str, vista_metodo: Optional[str]) -> str:
    return (
        f'<input type="hidden" name="ciclo" value="{esc(ciclo_key)}">'
        f'<input type="hidden" name="vista_metodo" value="{esc(vista_metodo or "")}">'
    )


def render_movimento(
    tipo: str, item: object, ciclo_key: str, vista_metodo: Optional[str]
) -> str:
    nascosti = hidden_vista(ciclo_key, vista_metodo)
    if tipo == "entrata":
        movimento = {
            "tipo": "entrata",
            "id": item.id,
            "data": item.data.isoformat(),
            "descrizione": item.descrizione or "",
            "importo": round(float(item.importo or 0), 2),
            "provenienza": item.provenienza or "",
        }
        meta = f"Entrata · {esc(item.provenienza or 'provenienza non indicata')}"
        badge = '<span class="badge badge-green">entrata</span>'
        importo_cls = "positive"
        importo_txt = fmt_money(item.importo, segno=True)
        azioni = (
            f'<button type="button" class="icon-btn small" data-mov=\'{json_attr(movimento)}\' '
            'onclick="openRicorrenzaFromMov(this)" title="Rendi questa entrata ricorrente (mensile/annuale)" aria-label="Rendi ricorrente">↻</button>'
            f'<button type="button" class="icon-btn small" data-mov=\'{json_attr(movimento)}\' '
            'onclick="openEdit(this)" title="Modifica entrata" aria-label="Modifica entrata">✎</button>'
            f'<form method="post" action="/delete-entrata/{item.id}" class="inline" '
            'onsubmit="return confirm(\'Eliminare questa entrata?\');">'
            f"{nascosti}"
            '<button type="submit" class="icon-btn small danger" title="Elimina entrata" '
            'aria-label="Elimina entrata">🗑</button></form>'
        )
    else:
        movimento = {
            "tipo": "spesa",
            "id": item.id,
            "data": item.data.isoformat(),
            "data_acquisto": item.data_acquisto.isoformat() if item.data_acquisto else "",
            "descrizione": item.descrizione or "",
            "importo": round(float(item.importo or 0), 2),
            "metodo": item.metodo or "",
            "tipo_spesa": item.tipo or TIPO_IMMEDIATO,
            "pagata": bool(item.pagata),
        }
        tipo_label = "ricorrente" if item.tipo != TIPO_IMMEDIATO else "variabile"
        if is_carta_credito(item.metodo):
            stato = "pagata" if item.pagata else "da pagare"
            meta = f"Spesa · {esc(item.metodo or '—')} · {tipo_label} · {stato}"
            if item.data_acquisto:
                meta += f" · acquisto {data_breve(item.data_acquisto)}"
        else:
            meta = f"{esc(item.metodo or '—')} · {tipo_label}"
        badge = (
            '<span class="badge badge-green">pagata</span>'
            if item.pagata
            else '<span class="badge badge-amber badge-unpaid">da pagare</span>'
        )
        importo_cls = "negative"
        importo_txt = fmt_money(-abs(float(item.importo or 0)), segno=True)
        toggle_titolo = "Segna come non pagata" if item.pagata else "Segna come pagata"
        toggle_segno = "✓" if item.pagata else "○"
        toggle_cls = " paid" if item.pagata else ""
        azioni = (
            f'<form method="post" action="/toggle-pagata/{item.id}" class="inline">'
            f"{nascosti}"
            f'<button type="submit" class="icon-btn small{toggle_cls}" title="{toggle_titolo}" '
            f'aria-label="{toggle_titolo}">{toggle_segno}</button></form>'
            f'<button type="button" class="icon-btn small" data-mov=\'{json_attr(movimento)}\' '
            'onclick="openRicorrenzaFromMov(this)" title="Rendi questa spesa ricorrente (mensile/annuale)" aria-label="Rendi ricorrente">↻</button>'
            f'<button type="button" class="icon-btn small" data-mov=\'{json_attr(movimento)}\' '
            'onclick="openEdit(this)" title="Modifica spesa" aria-label="Modifica spesa">✎</button>'
            f'<form method="post" action="/delete-spesa/{item.id}" class="inline" '
            'onsubmit="return confirm(\'Eliminare questa spesa?\');">'
            f"{nascosti}"
            '<button type="submit" class="icon-btn small danger" title="Elimina spesa" '
            'aria-label="Elimina spesa">🗑</button></form>'
        )

    unpaid_cls = " unpaid-row" if (tipo == "spesa" and not getattr(item, "pagata", True)) else ""
    return f"""
    <div class="mov-row{unpaid_cls}">
      <div class="mov-date"><strong>{data_breve(item.data)}</strong><span>{nome_giorno(item.data)}</span></div>
      <div class="mov-main">
        <div class="mov-title">{esc(item.descrizione or "Senza descrizione")} {badge}</div>
        <div class="mov-meta">{meta}</div>
      </div>
      <div class="mov-amount money {importo_cls}">{importo_txt}</div>
      <div class="mov-actions">{azioni}</div>
    </div>
    """


def render_spesa_fissa(
    item: object, ciclo_key: str, vista_metodo: Optional[str]
) -> str:
    nascosti = hidden_vista(ciclo_key, vista_metodo)
    movimento = {
        "tipo": "spesa",
        "id": item.id,
        "data": item.data.isoformat(),
        "data_acquisto": item.data_acquisto.isoformat() if item.data_acquisto else "",
        "descrizione": item.descrizione or "",
        "importo": round(float(item.importo or 0), 2),
        "metodo": item.metodo or "",
        "tipo_spesa": item.tipo or TIPO_IMMEDIATO,
        "pagata": bool(item.pagata),
    }
    stato = (
        '<span class="badge badge-green">pagata</span>'
        if item.pagata
        else '<span class="badge badge-amber badge-unpaid">da pagare</span>'
    )
    unpaid_cls = " unpaid-row" if not item.pagata else ""
    meta_fissa = (
        f"Spesa ricorrente · {esc(item.metodo or '—')}"
        + (f" · acquisto {data_breve(item.data_acquisto)}" if (is_carta_credito(item.metodo) and item.data_acquisto) else "")
        if is_carta_credito(item.metodo)
        else f"{esc(item.metodo or '—')} · ricorrente"
    )
    toggle_titolo = "Segna come non pagata" if item.pagata else "Segna come pagata"
    toggle_segno = "✓" if item.pagata else "○"
    toggle_cls = " paid" if item.pagata else ""
    return f"""
    <div class="mov-row fixed-row{unpaid_cls}">
      <div class="mov-date"><strong>{data_breve(item.data)}</strong><span>{nome_giorno(item.data)}</span></div>
      <div class="mov-main">
        <div class="mov-title">{esc(item.descrizione or "Senza descrizione")} {stato}</div>
        <div class="mov-meta">{meta_fissa}</div>
      </div>
      <div class="mov-amount money negative">{fmt_money(-abs(float(item.importo or 0)), segno=True)}</div>
      <div class="mov-actions">
        <form method="post" action="/toggle-pagata/{item.id}" class="inline">{nascosti}
          <button type="submit" class="icon-btn small{toggle_cls}" title="{toggle_titolo}" aria-label="{toggle_titolo}">{toggle_segno}</button>
        </form>
        <button type="button" class="icon-btn small" data-mov='{json_attr(movimento)}' onclick="openEdit(this)" title="Modifica spesa" aria-label="Modifica spesa">✎</button>
        <form method="post" action="/delete-serie" class="inline" onsubmit="return confirm('Eliminare questa spesa ricorrente dal ciclo corrente e da tutti i cicli futuri?');">
          {nascosti}
          <input type="hidden" name="id" value="{item.id}">
          <button type="submit" class="mini-btn" title="Elimina dal ciclo corrente e da tutti i cicli futuri">da qui in poi</button>
        </form>
        <form method="post" action="/delete-spesa/{item.id}" class="inline" onsubmit="return confirm('Eliminare questa spesa?');">
          {nascosti}
          <button type="submit" class="icon-btn small danger" title="Elimina spesa" aria-label="Elimina spesa">🗑</button>
        </form>
      </div>
    </div>
    """


def render_timeline_day(giorno: date, voci: dict, oggi: date) -> str:
    totale_entrate = sum(float(e.importo or 0) for e in voci["entrate"])
    totale_spese = sum(float(s.importo or 0) for s in voci["spese"])
    totali = []
    if totale_entrate:
        totali.append(f'<span class="money positive">+{fmt_money(totale_entrate)}</span>')
    if totale_spese:
        totali.append(f'<span class="money negative">-{fmt_money(totale_spese)}</span>')
    righe = []
    for entrata in voci["entrate"]:
        righe.append(
            f'<div class="tl-item"><span class="dot green"></span>'
            f'<span class="tl-desc">{esc(entrata.descrizione or "Entrata")}'
            f'<span class="muted"> · {esc(entrata.provenienza or "entrata")}</span></span>'
            f'<span class="tl-amount money positive">+{fmt_money(entrata.importo)}</span></div>'
        )
    for spesa in voci["spese"]:
        righe.append(
            f'<div class="tl-item"><span class="dot red"></span>'
            f'<span class="tl-desc">{esc(spesa.descrizione or "Spesa")}'
            f'<span class="muted"> · {esc(spesa.metodo or "—")}</span></span>'
            f'<span class="tl-amount money negative">-{fmt_money(spesa.importo)}</span></div>'
        )
    classe = "tl-day today" if giorno == oggi else "tl-day"
    return f"""
    <div class="{classe}">
      <div class="tl-day-head">
        <strong>{nome_giorno(giorno)} {giorno.day} {MESI[giorno.month - 1]}</strong>
        <span class="tl-totals">{" ".join(totali)}</span>
      </div>
      <div class="tl-items">{"".join(righe)}</div>
    </div>
    """


def render_chipbar(ctx: dict) -> str:
    chips = []
    voci = [("Tutti", "")] + [(metodo, metodo) for metodo in METODI]
    for label, valore in voci:
        params = {"ciclo": ctx["ciclo_key"]}
        if valore:
            params["metodo"] = valore
        href = "/?" + urlencode(params)
        attivo = " active" if (ctx["metodo"] or "") == valore else ""
        chips.append(
            f'<a class="chip{attivo}" href="{esc(href)}">{esc(label)}</a>'
        )
    return f"""
    <section class="chipbar" aria-label="Filtra le spese per metodo">
      <span class="chip-label">Metodo</span>
      {"".join(chips)}
    </section>
    """


def render_hero(ctx: dict) -> str:
    risultato = ctx["risultato"]
    oggi = ctx["oggi"]
    inizio = ctx["start"]
    fine = ctx["end"]
    ciclo_futuro = oggi < inizio
    if ciclo_futuro:
        saldo = ctx["netto_previsto_futuro"]
        budget = risultato.budget_giornaliero
        eyebrow_saldo = "Disponibile previsto (al netto fisse)"
        eyebrow_budget = "Budget / giorno previsto"
        progress_label = "Ciclo futuro · previsione su entrate e spese programmate"
    else:
        saldo = risultato.disponibile_netto
        budget = risultato.budget_giornaliero
        eyebrow_saldo = "Saldo disponibile"
        eyebrow_budget = "Budget / giorno"
        if oggi > fine:
            progress_label = "Ciclo concluso"
        else:
            progress_label = (
                f"Giorno {ctx['giorni_trascorsi']} di {ctx['giorni_totali']}"
                f" · {ctx['giorni_rimanenti']} giorni rimanenti"
            )
    saldo_cls = " negative" if saldo < 0 else ""
    budget_cls = " negative" if budget < 0 else ""
    return f"""
    <section class="hero card">
      <div class="hero-grid">
        <div class="hero-col">
          <div class="eyebrow">{eyebrow_saldo}</div>
          <div class="hero-value money{saldo_cls}">{fmt_money(saldo)}</div>
        </div>
        <div class="hero-col">
          <div class="eyebrow">{eyebrow_budget}</div>
          <div class="hero-value money{budget_cls}">{fmt_money(budget)}</div>
        </div>
      </div>
      <div class="progress-wrap">
        <div class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{ctx['progress']}">
          <div class="progress-fill" style="width:{ctx['progress']}%"></div>
        </div>
        <div class="progress-label"><span>{progress_label}</span><span>{ctx['progress']}%</span></div>
      </div>
    </section>

    """


def render_savings(ctx: dict) -> str:
    risultato = ctx["risultato"]
    avanzo_ciclo = risultato.risparmio_previsto_fine_ciclo
    prelievi = ctx.get("prelievi_salvadanaio", 0.0)
    riporto_residuo = round(ctx["riporto"] - prelievi, 2)
    riporto_totale = round(riporto_residuo + avanzo_ciclo, 2)
    classe = "positive" if riporto_totale >= 0 else "negative"
    badge = "In positivo" if riporto_totale >= 0 else "In rosso"
    dettaglio_prelievi = (
        f' − prelevati nel ciclo <span class="money negative">{fmt_money(prelievi)}</span>'
        if prelievi > 0
        else ""
    )
    return f"""
    <section class="savings card {classe}">
      <div class="savings-main">
        <div class="eyebrow">Salvadanaio / Riporto previsto a fine ciclo</div>
        <div class="savings-value money {classe}">{fmt_money(riporto_totale)}</div>
        <p class="savings-detail">
          Riporto precedente <span class="money">{fmt_money(ctx['riporto'])}</span>{dettaglio_prelievi}
          + avanzo previsto ciclo <span class="money">{fmt_money(avanzo_ciclo, segno=True)}</span>
          (entrate previste <span class="money positive">{fmt_money(ctx['entrate_previste'])}</span>,
          spese variabili previste <span class="money negative">{fmt_money(ctx['spese_previste'])}</span>).
        </p>
      </div>
      <div class="savings-badge {classe}">{badge}</div>
    </section>
    """


def render_sections(ctx: dict) -> str:
    risultato = ctx["risultato"]
    ciclo_key = ctx["ciclo_key"]
    vista_metodo = ctx["metodo"]
    oggi = ctx["oggi"]
    entrate = ctx["entrate"]
    spese_visibili = ctx["spese_visibili"]

    per_giorno: dict[date, dict] = {}
    if vista_metodo != "Da valutare":
        for entrata in entrate:
            per_giorno.setdefault(entrata.data, {"entrate": [], "spese": []})["entrate"].append(entrata)
    for spesa in spese_visibili:
        per_giorno.setdefault(spesa.data, {"entrate": [], "spese": []})["spese"].append(spesa)

    def build_day_card(giorno: date) -> str:
        voci = per_giorno[giorno]
        tot_e = sum(float(e.importo or 0) for e in voci["entrate"])
        tot_s = sum(float(s.importo or 0) for s in voci["spese"])
        totali_html = []
        if tot_e:
            totali_html.append(f'<span class="money positive">+{fmt_money(tot_e)}</span>')
        if tot_s:
            totali_html.append(f'<span class="money negative">-{fmt_money(tot_s)}</span>')

        badge_giorno = '<span class="badge badge-blue">Oggi</span>' if giorno == oggi else ""

        righe_giorno = "".join(
            render_movimento("entrata", e, ciclo_key, vista_metodo) for e in voci["entrate"]
        ) + "".join(
            render_movimento("spesa", s, ciclo_key, vista_metodo) for s in voci["spese"]
        )
        ha_spese_da_pagare = any(not getattr(s, "pagata", True) for s in voci["spese"])
        if ha_spese_da_pagare:
            day_cls = "day-group future"
        elif giorno == oggi:
            day_cls = "day-group today"
        else:
            day_cls = "day-group"

        return (
            f'<div class="{day_cls}">'
            f'<div class="day-group-head">'
            f'<div class="day-group-title"><strong>{nome_giorno(giorno)} {giorno.day} {MESI[giorno.month - 1]}</strong> {badge_giorno}</div>'
            f'<div class="day-group-totals">{" ".join(totali_html)}</div>'
            f'</div>'
            f'<div class="day-group-rows">{righe_giorno}</div>'
            f'</div>'
        )

    # 1. Movimenti di oggi
    totale_oggi = 0
    if oggi in per_giorno:
        voci_oggi = per_giorno[oggi]
        totale_oggi = len(voci_oggi["entrate"]) + len(voci_oggi["spese"])
        righe_oggi = build_day_card(oggi)
    else:
        righe_oggi = (
            '<div class="empty">Nessun movimento registrato per oggi'
            + (f" per il metodo {esc(vista_metodo)}." if vista_metodo else ".")
            + "</div>"
        )

    # 2. Movimenti del mese (tutti gli altri giorni in ordine cronologico)
    giorni_mese = sorted(
        (g for g in per_giorno.keys() if g != oggi),
        key=lambda g: g.toordinal(),
    )
    totale_mese = sum(
        len(per_giorno[g]["entrate"]) + len(per_giorno[g]["spese"])
        for g in giorni_mese
    )
    righe_mese = "".join(build_day_card(g) for g in giorni_mese)
    if not righe_mese:
        righe_mese = (
            '<div class="empty">Nessun altro movimento in questo ciclo'
            + (f" per il metodo {esc(vista_metodo)}." if vista_metodo else ".")
            + "</div>"
        )

    spese_fisse = [
        s for s in spese_visibili
        if s.tipo != TIPO_IMMEDIATO and ctx['start'] <= s.data <= ctx['end']
    ]
    spese_fisse.sort(key=lambda s: (s.data, s.id))
    righe_fisse = "".join(
        render_spesa_fissa(spesa, ciclo_key, vista_metodo) for spesa in spese_fisse
    )
    if not righe_fisse:
        righe_fisse = '<div class="empty">Nessuna spesa ricorrente registrata in questo ciclo.</div>'
    totale_fisse = sum(float(s.importo or 0) for s in spese_fisse)

    return f"""
    <div class="actions">
      <button type="button" class="btn btn-red" onclick="openModal('modal-spesa')">+ Spesa</button>
      <button type="button" class="btn btn-green" onclick="openModal('modal-entrata')">+ Entrata</button>
      <span class="actions-note">Registra un movimento nel ciclo selezionato</span>
    </div>

    {render_chipbar(ctx)}

    <section class="card accordion">
      <button type="button" class="accordion-head" data-collapse="movimenti-oggi" aria-expanded="true" aria-controls="movimenti-oggi" onclick="toggleCollapse('movimenti-oggi')">
        <span>Movimenti di oggi <span class="count">{totale_oggi}</span></span>
        <span class="chev" aria-hidden="true">▾</span>
      </button>
      <div class="accordion-body open" id="movimenti-oggi">
        {righe_oggi}
      </div>
    </section>

    <section class="card accordion">
      <button type="button" class="accordion-head" data-collapse="movimenti-mese" aria-expanded="true" aria-controls="movimenti-mese" onclick="toggleCollapse('movimenti-mese')">
        <span>Movimenti del mese <span class="count">{totale_mese}</span></span>
        <span class="chev" aria-hidden="true">▾</span>
      </button>
      <div class="accordion-body open" id="movimenti-mese">
        {righe_mese}
      </div>
    </section>

    <section class="card accordion">
      <button type="button" class="accordion-head" data-collapse="spese-fisse" aria-expanded="false" aria-controls="spese-fisse" onclick="toggleCollapse('spese-fisse')">
        <span>Spese ricorrenti <span class="count">{len(spese_fisse)} · <span class="money">{fmt_money(totale_fisse)}</span></span></span>
        <span class="chev" aria-hidden="true">▾</span>
      </button>
      <div class="accordion-body" id="spese-fisse">
        {righe_fisse}
      </div>
    </section>
    <section class="card accordion">
      <button type="button" class="accordion-head" data-collapse="quadro-generale" aria-expanded="false" aria-controls="quadro-generale" onclick="toggleCollapse('quadro-generale')">
        <span>Quadro generale e PAC <span class="count">PAC {f"{fmt_money(ctx['pac_fisso'])}" if ctx['pac_fisso'] > 0 else f"{ctx['pac_perc'] * 100:.0f}%"} · Salvadanaio <span class="money">{fmt_money(max(0.0, round(ctx['riporto'] - ctx.get('prelievi_salvadanaio', 0.0), 2)))}</span></span></span>
        <span class="chev" aria-hidden="true">▾</span>
      </button>
      <div class="accordion-body" id="quadro-generale" style="padding:18px 22px">
        <div class="hero-grid">
          <div class="hero-col">
            <div class="stat-row" style="margin-top:0">
              <div class="stat"><span class="stat-label">Entrate</span><strong class="stat-value money positive">{fmt_money(ctx['entrate_totali'])}</strong></div>
              <div class="stat"><span class="stat-label">Uscite</span><strong class="stat-value money negative">{fmt_money(ctx['uscite_totali'])}</strong></div>
              <div class="stat"><span class="stat-label">Riporto</span><strong class="stat-value money">{fmt_money(max(0.0, round(ctx['riporto'] - ctx.get('prelievi_salvadanaio', 0.0), 2)))}</strong></div>
            </div>
          </div>
          <div class="hero-col">
            <div class="stat-row" style="margin-top:0">
              <div class="stat"><span class="stat-label">Spese ricorrenti</span><strong class="stat-value money">{fmt_money(ctx['spese_fisse_display'])}</strong></div>
              <div class="stat"><span class="stat-label">Spese variabili</span><strong class="stat-value money">{fmt_money(ctx['spese_variabili_display'])}</strong></div>
              <div class="stat"><span class="stat-label">Giorni</span><strong class="stat-value">{ctx['giorni_rimanenti']}</strong></div>
            </div>
          </div>
        </div>
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
          <div class="hint" style="margin:0">Accantonato nel ciclo: <strong>{fmt_money(risultato.pac_obiettivo + risultato.cuscinetto)}</strong> (PAC {f"{fmt_money(ctx['pac_fisso'])}/ciclo" if ctx['pac_fisso'] > 0 else f"{ctx['pac_perc'] * 100:.0f}%"} · cuscinetto {f"{fmt_money(ctx['cuscinetto_fisso'])}/ciclo" if ctx['cuscinetto_fisso'] > 0 else f"{ctx['cuscinetto_perc'] * 100:.0f}%"}) · Disponibile netto ciclo: <strong>{fmt_money(risultato.disponibile_netto)}</strong></div>
          <form method="post" action="/config" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <input type="hidden" name="ciclo" value="{esc(ctx['ciclo_key'])}">
            <input type="hidden" name="vista_metodo" value="{esc(ctx['metodo'] or '')}">
            <div style="display:inline-flex;align-items:center;gap:4px;font-size:.8rem;font-weight:700;color:var(--muted)">
              <span>PAC</span>
              <input type="text" name="pac" inputmode="decimal" value="{fmt_input(ctx['pac_fisso']) if ctx['pac_fisso'] > 0 else f"{ctx['pac_perc'] * 100:.0f}"}" style="width:68px;padding:6px 8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text)">
              <select name="pac_modo" style="padding:6px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-weight:700">
                <option value="perc"{" selected" if ctx['pac_fisso'] <= 0 else ""}>%</option>
                <option value="eur"{" selected" if ctx['pac_fisso'] > 0 else ""}>€</option>
              </select>
            </div>
            <div style="display:inline-flex;align-items:center;gap:4px;font-size:.8rem;font-weight:700;color:var(--muted)">
              <span>Cuscinetto</span>
              <input type="text" name="cuscinetto" inputmode="decimal" value="{fmt_input(ctx['cuscinetto_fisso']) if ctx['cuscinetto_fisso'] > 0 else f"{ctx['cuscinetto_perc'] * 100:.0f}"}" style="width:68px;padding:6px 8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text)">
              <select name="cuscinetto_modo" style="padding:6px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-weight:700">
                <option value="perc"{" selected" if ctx['cuscinetto_fisso'] <= 0 else ""}>%</option>
                <option value="eur"{" selected" if ctx['cuscinetto_fisso'] > 0 else ""}>€</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary" style="padding:7px 12px;font-size:.85rem">Salva</button>
          </form>
        </div>
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
          <div class="hint" style="margin:0">Attingi dal salvadanaio (disponibile: <strong>{fmt_money(max(0.0, round(ctx['riporto'] - ctx.get('prelievi_salvadanaio', 0.0), 2)))}</strong>)</div>
          <form method="post" action="/preleva-salvadanaio" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <input type="hidden" name="ciclo" value="{esc(ctx['ciclo_key'])}">
            <input type="hidden" name="vista_metodo" value="{esc(ctx['metodo'] or '')}">
            <input type="text" name="importo" inputmode="decimal" placeholder="0,00" onblur="formatImporto(this)" {"disabled" if round(ctx['riporto'] - ctx.get('prelievi_salvadanaio', 0.0), 2) <= 0 else "required"} style="width:90px;padding:6px 8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text)">
            <button type="submit" class="btn btn-ghost" {"disabled" if round(ctx['riporto'] - ctx.get('prelievi_salvadanaio', 0.0), 2) <= 0 else ""} style="padding:7px 12px;font-size:.85rem">Preleva nel budget</button>
          </form>
        </div>
      </div>
    </section>
    """


def render_modals(ctx: dict) -> str:
    ciclo_key = ctx["ciclo_key"]
    vista_metodo = ctx["metodo"] or ""
    oggi = ctx["oggi"].isoformat()
    nascosti = hidden_vista(ciclo_key, vista_metodo)
    provenienze = (
        "<datalist id=\"provenienze\">"
        "<option>Stipendio</option>"
        "<option>Bonifico</option><option>Rimborso</option><option>Altro</option>"
        "</datalist>"
    )
    return f"""
    <div class="modal-overlay" id="modal-spesa" role="dialog" aria-modal="true" aria-labelledby="titolo-spesa">
      <div class="modal">
        <div class="modal-head">
          <h2 id="titolo-spesa">Nuova spesa</h2>
          <button type="button" class="icon-btn" onclick="closeModal('modal-spesa')" aria-label="Chiudi">×</button>
        </div>
        <form method="post" action="/add-spesa" id="form-nuova-spesa" class="form-grid modal-body">
          {nascosti}
          <label class="field span2">Descrizione
            <input type="text" name="descrizione" required maxlength="200" placeholder="Es. Spesa al supermercato">
          </label>
          <label class="field">Importo
            <input type="text" name="importo" inputmode="decimal" required placeholder="0,00" onblur="formatImporto(this)">
          </label>
          <label class="field" id="spesa-wrap-data">Data
            <input type="date" name="data" id="spesa-data" value="{oggi}" required>
          </label>
          <label class="field" id="spesa-wrap-acq" style="display:none">Data acquisto <span class="hint">cutoff automatico</span>
            <input type="date" name="data_acquisto" id="spesa-data-acquisto" value="{oggi}">
          </label>
          <label class="field">Metodo
            <select name="metodo" id="spesa-metodo" onchange="aggiornaCampiCartaSpesa()">{metodo_options("Contanti")}</select>
          </label>
          <label class="field">Tipo
            <select name="tipo">{tipo_options(TIPO_IMMEDIATO)}</select>
          </label>
          <label class="field span2">Ricorrenza automatica
            <select name="ricorrenza" onchange="document.getElementById('spesa-rate-box').style.display = this.value === 'nessuna' ? 'none' : 'grid'">
              <option value="nessuna" selected>Singola (solo questo ciclo)</option>
              <option value="mensile">Mensile (ogni mese allo stesso giorno)</option>
              <option value="annuale">Annuale (ogni anno alla stessa data)</option>
            </select>
          </label>
          <div id="spesa-rate-box" class="form-subgrid span2" style="display:none">
            <label class="field">Numero di rate <span class="hint">opzionale</span>
              <input type="number" name="num_rate" min="1" max="600" placeholder="Es. 12">
            </label>
            <label class="field">Oppure data ultima rata <span class="hint">opzionale</span>
              <input type="date" name="data_fine">
            </label>
          </div>
          <label class="check span2" id="spesa-wrap-pagata"><input type="checkbox" name="pagata" checked> Già pagata</label>
          <div class="modal-foot span2">
            <button type="button" class="btn btn-ghost" onclick="closeModal('modal-spesa')">Annulla</button>
            <button type="submit" class="btn btn-red">Salva spesa</button>
          </div>
        </form>
      </div>
    </div>

    <div class="modal-overlay" id="modal-entrata" role="dialog" aria-modal="true" aria-labelledby="titolo-entrata">
      <div class="modal">
        <div class="modal-head">
          <h2 id="titolo-entrata">Nuova entrata</h2>
          <button type="button" class="icon-btn" onclick="closeModal('modal-entrata')" aria-label="Chiudi">×</button>
        </div>
        <form method="post" action="/add-entrata" class="form-grid modal-body">
          {nascosti}
          <label class="field span2">Descrizione
            <input type="text" name="descrizione" required maxlength="200" placeholder="Es. Stipendio novembre">
          </label>
          <label class="field">Importo
            <input type="text" name="importo" inputmode="decimal" required placeholder="0,00" onblur="formatImporto(this)">
          </label>
          <label class="field">Data
            <input type="date" name="data" value="{oggi}" required>
          </label>
          <label class="field span2">Provenienza
            <input type="text" name="provenienza" list="provenienze" maxlength="120" placeholder="Stipendio, pensione, rimborso...">
          </label>
          <label class="field span2">Ricorrenza automatica
            <select name="ricorrenza" onchange="document.getElementById('entrata-rate-box').style.display = this.value === 'nessuna' ? 'none' : 'grid'">
              <option value="nessuna" selected>Singola (solo questo ciclo)</option>
              <option value="mensile">Mensile (ogni mese allo stesso giorno)</option>
              <option value="annuale">Annuale (ogni anno alla stessa data)</option>
            </select>
          </label>
          <div id="entrata-rate-box" class="form-subgrid span2" style="display:none">
            <label class="field">Numero di rate <span class="hint">opzionale</span>
              <input type="number" name="num_rate" min="1" max="600" placeholder="Es. 12">
            </label>
            <label class="field">Oppure data ultima rata <span class="hint">opzionale</span>
              <input type="date" name="data_fine">
            </label>
          </div>
          {provenienze}
          <div class="modal-foot span2">
            <button type="button" class="btn btn-ghost" onclick="closeModal('modal-entrata')">Annulla</button>
            <button type="submit" class="btn btn-green">Salva entrata</button>
          </div>
        </form>
      </div>
    </div>

    <div class="modal-overlay" id="modal-edit" role="dialog" aria-modal="true" aria-labelledby="titolo-edit">
      <div class="modal">
        <div class="modal-head">
          <h2 id="titolo-edit">Modifica movimento</h2>
          <button type="button" class="icon-btn" onclick="closeModal('modal-edit')" aria-label="Chiudi">×</button>
        </div>
        <form method="post" id="edit-form" action="/update-movimento/spesa/0" class="form-grid modal-body">
          {nascosti}
          <label class="field span2">Categoria
            <select name="nuovo_tipo" id="edit-categoria" onchange="toggleEditCategoria()">
              <option value="spesa">Spesa (uscita)</option>
              <option value="entrata">Entrata</option>
            </select>
          </label>
          <label class="field span2">Descrizione
            <input type="text" name="descrizione" id="edit-descrizione" required maxlength="200">
          </label>
          <label class="field">Importo
            <input type="text" name="importo" id="edit-importo" inputmode="decimal" required onblur="formatImporto(this)">
          </label>
          <label class="field">Data
            <input type="date" name="data" id="edit-data" required>
          </label>
          <div class="form-subgrid span2" id="edit-entrata-fields">
            <label class="field">Provenienza
              <input type="text" name="provenienza" id="edit-provenienza" list="provenienze" maxlength="120">
            </label>
          </div>
          <div class="form-subgrid span2" id="edit-spesa-fields">
            <label class="field" id="edit-wrap-acq" style="display:none">Data acquisto <span class="hint">cutoff automatico</span>
              <input type="date" name="data_acquisto" id="edit-data-acquisto">
            </label>
            <label class="field">Metodo
              <select name="metodo" id="edit-metodo" onchange="aggiornaCampiCartaEdit()">{metodo_options()}</select>
            </label>
            <label class="field">Tipo
              <select name="tipo" id="edit-tipo-spesa">{tipo_options()}</select>
            </label>
            <label class="check" id="edit-wrap-pagata"><input type="checkbox" name="pagata" id="edit-pagata"> Pagata</label>
          </div>
          <div class="modal-foot span2">
            <button type="button" class="btn btn-ghost" onclick="closeModal('modal-edit')">Annulla</button>
            <button type="submit" class="btn btn-primary">Salva modifiche</button>
          </div>
        </form>
      </div>
    </div>
    <div class="modal-overlay" id="modal-ricorrenze" role="dialog" aria-modal="true" aria-labelledby="titolo-ricorrenze">
      <div class="modal">
        <div class="modal-head">
          <h2 id="titolo-ricorrenze">Ricorrenze e rate automatiche</h2>
          <button type="button" class="icon-btn" onclick="resetFormRicorrenza(); closeModal('modal-ricorrenze')" aria-label="Chiudi">×</button>
        </div>
        <div class="modal-body" style="display:grid;gap:16px">
          <p class="hint" id="ric-form-hint">Imposta il numero di rate oppure la data dell'ultima rata: il sistema genererà i movimenti fino alla scadenza indicata.</p>
          <form method="post" action="/add-ricorrenza" id="form-ricorrenza" class="form-grid" style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc">
            {nascosti}
            <label class="field">Categoria
              <select name="categoria" id="ric-categoria">
                <option value="spesa">Spesa ricorrente</option>
                <option value="entrata">Entrata ricorrente</option>
              </select>
            </label>
            <label class="field">Frequenza
              <select name="frequenza" id="ric-frequenza">
                <option value="mensile">Mensile (ogni mese)</option>
                <option value="annuale">Annuale (ogni anno)</option>
              </select>
            </label>
            <label class="field span2">Descrizione
              <input type="text" name="descrizione" id="ric-descrizione" required maxlength="200" placeholder="Es. Fiat Panda, Affitto, Regalo Luca...">
            </label>
            <label class="field">Importo
              <input type="text" name="importo" id="ric-importo" inputmode="decimal" required placeholder="0,00" onblur="formatImporto(this)">
            </label>
            <label class="field">Data prima/prossima scadenza
              <input type="date" name="data_inizio" id="ric-data-inizio" value="{oggi}" required>
            </label>
            <label class="field">Metodo (se spesa)
              <select name="metodo" id="ric-metodo">{metodo_options("SDD")}</select>
            </label>
            <label class="field">Provenienza (se entrata)
              <select id="ric-prov-tipo" onchange="var inp=document.getElementById('ric-provenienza'); if(this.value==='Stipendio'){{inp.value='Stipendio';inp.style.display='none';}}else{{if(inp.value==='Stipendio')inp.value='';inp.style.display='block';inp.focus();}}">
                <option value="Stipendio" selected>Stipendio</option>
                <option value="Altro">Altro (inserisci testo)</option>
              </select>
              <input type="text" name="provenienza" id="ric-provenienza" value="Stipendio" style="display:none;margin-top:6px" maxlength="120" placeholder="Scrivi provenienza...">
            </label>
            <label class="field">Numero di rate <span class="hint">opzionale</span>
              <input type="number" name="num_rate" id="ric-num-rate" min="1" max="600" placeholder="Es. 12">
            </label>
            <label class="field">Oppure data ultima rata <span class="hint">opzionale</span>
              <input type="date" name="data_fine" id="ric-data-fine">
            </label>
            <label class="field span2" style="flex-direction:row;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" name="pagata" id="ric-pagata" value="1" style="width:18px;height:18px">
              <span>Già pagata (addebito automatico)</span>
            </label>
            <div class="span2" style="display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap">
              <button type="button" class="btn btn-ghost" id="btn-cancel-edit-ric" style="display:none" onclick="resetFormRicorrenza()">Annulla modifica</button>
              <button type="submit" class="btn btn-primary" id="btn-submit-ric">Attiva ricorrenza automatica</button>
            </div>
          </form>
          <div class="ricorrenze-list">
            <h3 style="margin-bottom:8px">Regole attive ({len(ctx.get("ricorrenze", []))})</h3>
            {ctx.get("righe_ricorrenze", "")}
          </div>
        </div>
      </div>
    </div>
   
    <div class="modal-overlay" id="modal-wizard" role="dialog" aria-modal="true" aria-labelledby="titolo-wizard">
      <div class="modal" style="max-width:640px">
        <div class="modal-head">
          <div>
            <h2 id="titolo-wizard">⚙️ Configurazione iniziale</h2>
            <p class="hint" id="wiz-subtitle">Personalizza ciclo contabile, carte di credito, risparmio e credenziali</p>
          </div>
          <button type="button" class="icon-btn" onclick="closeModal('modal-wizard')" aria-label="Chiudi">×</button>
        </div>
        <form method="post" action="/save-wizard" id="form-wizard" class="modal-body" style="display:grid;gap:16px">
          {nascosti}
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px">
            <button type="button" class="btn btn-primary" id="wiz-tab-1" onclick="openWizardStep(1)">1. Ciclo</button>
            <button type="button" class="btn btn-ghost" id="wiz-tab-2" onclick="openWizardStep(2)">2. Carte</button>
            <button type="button" class="btn btn-ghost" id="wiz-tab-3" onclick="openWizardStep(3)">3. Risparmio</button>
            <button type="button" class="btn btn-ghost" id="wiz-tab-4" onclick="openWizardStep(4)">4. Account</button>
          </div>

          <div id="wiz-step-1" style="display:grid;gap:14px">
            <div style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc;display:grid;gap:12px">
              <strong>Quando inizia il tuo mese contabile?</strong>
              <p class="hint">Se ricevi lo stipendio il 23 o il 27 del mese, imposta quel giorno così il budget mensile parte esattamente da quando ti entra lo stipendio.</p>
              <label class="field">Giorno di inizio ciclo (1 - 28)
                <input type="number" name="giorno_inizio_ciclo" id="wiz-giorno" min="1" max="28" value="{ctx.get('giorno_inizio_ciclo', 1)}" required>
              </label>
              <label class="field">Data di partenza contabilità
                <input type="date" name="data_inizio_contabilita" id="wiz-data-start" value="{ctx.get('data_inizio_contabilita', str(oggi))}" required>
              </label>
            </div>
            <div style="display:flex;justify-content:flex-end">
              <button type="button" class="btn btn-primary" onclick="openWizardStep(2)">Avanti: Carte di credito →</button>
            </div>
          </div>

          <div id="wiz-step-2" style="display:none;gap:14px">
            <div style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc;display:grid;gap:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                <strong>Le tue Carte di Credito</strong>
                <button type="button" class="btn btn-ghost" onclick="aggiungiRigaCarta('', 15, 0)">+ Aggiungi carta</button>
              </div>
              <p class="hint">Indica il giorno di chiusura estratto conto (cutoff) e il giorno di addebito sul conto (0 = ultimo giorno del mese). I pagamenti immediati (Bancomat, Bonifico, SDD, Contanti) sono già inclusi.</p>
              <div id="wiz-carte-list" style="display:grid;gap:10px"></div>
              <input type="hidden" name="carte_json" id="wiz-carte-json" value="[]">
            </div>
            <div style="display:flex;justify-content:space-between">
              <button type="button" class="btn btn-ghost" onclick="openWizardStep(1)">← Indietro</button>
              <button type="button" class="btn btn-primary" onclick="openWizardStep(3)">Avanti: Risparmio →</button>
            </div>
          </div>

          <div id="wiz-step-3" style="display:none;gap:14px">
            <div style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc;display:grid;gap:12px">
              <strong>Obiettivo Salvadanaio (PAC e Cuscinetto)</strong>
              <p class="hint">Scegli quanto vuoi accantonare ogni mese prima di calcolare il tuo budget giornaliero spendibile (puoi lasciare 0 e modificarlo quando vuoi).</p>
              <div class="form-grid">
                <label class="field">PAC % sul disponibile
                  <input type="number" step="0.5" min="0" max="100" name="pac_percentuale" value="{round(ctx.get('pac_perc', 0.10) * 100, 1)}">
                </label>
                <label class="field">Oppure PAC fisso (€/mese)
                  <input type="number" step="1" min="0" name="pac_fisso" value="{round(ctx.get('pac_fisso', 0.0), 2)}">
                </label>
                <label class="field">Cuscinetto %
                  <input type="number" step="0.5" min="0" max="100" name="cuscinetto_percentuale" value="{round(ctx.get('cuscinetto_perc', 0.0) * 100, 1)}">
                </label>
                <label class="field">Oppure Cuscinetto fisso (€/mese)
                  <input type="number" step="1" min="0" name="cuscinetto_fisso" value="{round(ctx.get('cuscinetto_fisso', 0.0), 2)}">
                </label>
              </div>
            </div>
            <div style="display:flex;justify-content:space-between">
              <button type="button" class="btn btn-ghost" onclick="openWizardStep(2)">← Indietro</button>
              <button type="button" class="btn btn-primary" onclick="openWizardStep(4)">Avanti: Account →</button>
            </div>
          </div>

          <div id="wiz-step-4" style="display:none;gap:14px">
            <div style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc;display:grid;gap:12px">
              <strong>Credenziali di accesso locali</strong>
              <p class="hint">Puoi aggiornare in qualsiasi momento il tuo nome utente o impostare una nuova password per l'accesso locale.</p>
              <label class="field">Nome Utente (min. 3 caratteri)
                <input type="text" name="nuovo_username" minlength="3" maxlength="50" value="{esc(str(ctx.get('auth_user', '')))}" autocomplete="username">
              </label>
              <label class="field">Nuova Password (lascia vuoto per mantenere l'attuale)
                <input type="password" name="nuova_password" minlength="4" maxlength="100" placeholder="••••••••" autocomplete="new-password">
              </label>
            </div>
            <div style="display:flex;justify-content:space-between;gap:8px">
              <button type="button" class="btn btn-ghost" onclick="openWizardStep(3)">← Indietro</button>
              <button type="submit" class="btn btn-green" onclick="preparaCarteJson()">✓ Salva configurazione</button>
            </div>
          </div>
        </form>
      </div>
    </div>

    <div class="modal-overlay" id="modal-cerca" role="dialog" aria-modal="true" aria-labelledby="titolo-cerca">
      <div class="modal">
        <div class="modal-head">
          <h2 id="titolo-cerca">🔍 Cerca movimenti</h2>
          <button type="button" class="icon-btn" onclick="closeModal('modal-cerca')" aria-label="Chiudi">×</button>
        </div>
        <div class="modal-body" style="display:grid;gap:14px">
          <form id="form-cerca" onsubmit="eseguiRicercaMovimenti(event)" class="form-grid" style="padding:14px;border:1px solid var(--border);border-radius:12px;background:#f8fafc">
            <label class="field span2">Nome, descrizione, metodo o provenienza
              <input type="text" id="cerca-q" placeholder="Es. Zalando, Affitto, AmEx, Stipendio..." autocomplete="off">
            </label>
            <label class="field">Data da <span class="hint">opzionale</span><input type="date" id="cerca-da"></label>
            <label class="field">Data a <span class="hint">opzionale</span><input type="date" id="cerca-a"></label>
            <div class="span2" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
              <button type="button" class="btn btn-ghost" onclick="resetRicercaMovimenti()">Pulisci</button>
              <button type="submit" class="btn btn-primary">🔍 Cerca</button>
            </div>
          </form>
          <div id="cerca-riepilogo" class="hint" style="font-weight:700">Inserisci un nome e/o una data e premi Cerca.</div>
          <div id="cerca-risultati" style="display:grid;gap:8px;max-height:52vh;overflow-y:auto"></div>
        </div>
      </div>
    </div>
    """


def render_dashboard(ctx: dict) -> str:
    prev_url = ctx.get("prev_ciclo_url")
    next_url = ctx.get("next_ciclo_url")
    is_corrente = ctx.get("is_ciclo_corrente", True)

    btn_prev = (
        f'<a class="btn btn-ghost" href="{esc(prev_url)}" id="nav-prev-ciclo">← {esc(ctx.get("prev_etichetta", "Precedente"))}</a>'
        if prev_url
        else '<span class="btn btn-ghost" style="opacity:.4;pointer-events:none">← Inizio</span>'
    )
    btn_next = (
        f'<a class="btn btn-primary" href="{esc(next_url)}" id="nav-next-ciclo">{esc(ctx.get("next_etichetta", "Successivo"))} →</a>'
        if next_url
        else '<span class="btn btn-ghost" style="opacity:.55;pointer-events:none">Fine rate e dati</span>'
    )
    badge_oggi = (
        '<span class="badge badge-blue">Ciclo attuale</span>'
        if is_corrente
        else '<a href="/" class="badge badge-amber" style="text-decoration:none">Torna al ciclo attuale</a>'
    )
    nav_bar = (
        '<nav class="card" style="padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap" aria-label="Navigazione cicli">'
        + btn_prev
        + f'<div style="display:flex;flex-direction:column;align-items:center;gap:3px;text-align:center"><strong>{esc(ctx["etichetta"])}</strong><span class="hint">{esc(ctx["range_label"])}</span>{badge_oggi}</div>'
        + btn_next
        + "</nav>"
    )

    return (
        '<!DOCTYPE html>\n<html lang="it">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="theme-color" content="#2563eb"><link rel="manifest" href="/manifest.webmanifest?v=2"><link rel="icon" type="image/svg+xml" href="/icon.svg?v=2"><link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png?v=2"><link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=2"><meta name="apple-mobile-web-app-title" content="Bilancio"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes">\n'
        "<title>Bilancio familiare · Risparmio</title>\n"
        "<style>"
        + CSS
        + "</style>\n</head>\n<body>\n"
        '<header class="topbar">\n'
        '  <div class="container topbar-inner">\n'
        '    <div class="brand">\n'
        '      <div class="brand-mark" aria-hidden="true">€</div>\n'
        "      <div>\n"
        f'        <h1>{esc(ctx["etichetta"]).upper()}</h1>\n'
        f'        <div class="brand-sub" style="margin-top:2px;font-weight:600;color:var(--text)"><span id="roma-clock">{esc(ctx.get("roma_now_label", ""))}</span></div>\n'
        "      </div>\n"
        "    </div>\n"
        '    <div class="topbar-actions">\n'
        '      <button type="button" class="btn btn-ghost" onclick="openWizardStep(1); openModal(\'modal-wizard\')" title="Configura ciclo, carte di credito, risparmio e account">⚙️ Configura</button>\n'
        f'<button type="button" class="icon-btn" onclick="openModal(\'modal-cerca\')" title="Cerca movimenti per nome o data" aria-label="Cerca movimenti">🔍</button>\n'
        + f'<button type="button" class="btn btn-ghost" onclick="openModal(\'modal-ricorrenze\')" title="Gestisci spese ed entrate ricorrenti automatiche">↻ Ricorrenze ({len(ctx.get("ricorrenze", []))})</button>\n'
        f'      <a class="btn btn-ghost hide-mobile" href="/export-csv?ciclo={esc(ctx["ciclo_key"])}" title="Esporta i movimenti del ciclo in CSV">Esporta CSV</a>\n'
        '      <button type="button" class="icon-btn eye" id="eye-btn" onclick="toggleMoney()" title="Nascondi cifre" aria-label="Nascondi cifre">👁</button>\n'
        '      <a class="icon-btn" href="/logout" title="Esci dalla sessione" aria-label="Esci">⎋</a>\n'
        "    </div>\n"
        "  </div>\n"
        "</header>\n"
        '<main class="container main">\n'
        + render_hero(ctx)
        + render_savings(ctx)
        + render_sections(ctx)
        + nav_bar
        + "</main>\n"
        '<footer class="container footer">Archivio locale privato · SQLite</footer>\n'
        + render_modals(ctx)
        + "<script>"
        + JS
        + f"""</script>
<script>(function(){{var rc=document.getElementById('roma-clock');if(!rc)return;function u(){{var s=new Intl.DateTimeFormat('it-IT',{{timeZone:'Europe/Rome',weekday:'short',day:'numeric',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}}).format(new Date());rc.textContent=s.charAt(0).toUpperCase()+s.slice(1);}}u();setInterval(u,15000);}})();</script>
<script>(function(){{var p=new URLSearchParams(location.search);if(p.get('ok')==='1'){{p.delete('ok');var q=p.toString();history.replaceState(null,'',location.pathname+(q?'?'+q:''));var t=document.createElement('div');t.textContent='✓ Salvato in locale';t.style.cssText='position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#16a34a;color:#fff;padding:11px 20px;border-radius:999px;font-size:.9rem;font-weight:700;box-shadow:0 10px 25px rgba(22,163,74,.35);z-index:9999;transition:opacity .3s ease';document.body.appendChild(t);setTimeout(function(){{t.style.opacity='0';setTimeout(function(){{t.remove();}},300);}},2400);}}}})();</script>
<script>
window.CARTE_CREDITO = {json.dumps([c["nome"] for c in ctx.get("carte_credito", [])])};
window.CARTE_CONFIG_INIT = {json.dumps(ctx.get("carte_credito", []))};
window.WIZARD_AUTO_OPEN = {str(not ctx.get("wizard_completato", True)).lower()};

window.openWizardStep = function(n){{
  for(var i=1;i<=4;i++){{
    var s = document.getElementById("wiz-step-"+i);
    var t = document.getElementById("wiz-tab-"+i);
    if(s) s.style.display = (i===n) ? "grid" : "none";
    if(t) t.className = (i===n) ? "btn btn-primary" : "btn btn-ghost";
  }}
}};

window.aggiungiRigaCarta = function(nome, cutoff, addebito){{
  var list = document.getElementById("wiz-carte-list");
  if(!list) return;
  var row = document.createElement("div");
  row.className = "wiz-card-row";
  row.style.cssText = "display:grid;grid-template-columns:1.4fr 1fr 1fr auto;gap:8px;align-items:end;padding:10px;border:1px solid var(--border);border-radius:10px;background:#fff";
  row.innerHTML =
    '<label class="field">Nome carta<input type="text" class="wc-nome" placeholder="Es. Visa, AmEx" value="'+(nome||"").replace(/"/g,"&quot;")+'" maxlength="40"></label>' +
    '<label class="field">Cutoff (gg)<input type="number" class="wc-cutoff" min="1" max="28" value="'+(cutoff||15)+'"></label>' +
    '<label class="field">Addebito (0=fine mese)<input type="number" class="wc-addebito" min="0" max="28" value="'+(addebito!==undefined?addebito:0)+'"></label>' +
    '<button type="button" class="icon-btn danger" onclick="this.closest(&#39;.wiz-card-row&#39;).remove()" title="Rimuovi carta">🗑</button>';
  list.appendChild(row);
}};

window.preparaCarteJson = function(){{
  var rows = document.querySelectorAll("#wiz-carte-list .wiz-card-row");
  var out = [];
  rows.forEach(function(r){{
    var nome = (r.querySelector(".wc-nome").value || "").trim();
    var cutoff = parseInt(r.querySelector(".wc-cutoff").value || "15", 10);
    var addebito = parseInt(r.querySelector(".wc-addebito").value || "0", 10);
    if(nome) out.push({{nome: nome, cutoff: cutoff, addebito: addebito}});
  }});
  var hid = document.getElementById("wiz-carte-json");
  if(hid) hid.value = JSON.stringify(out);
}};

document.addEventListener("DOMContentLoaded", function(){{
  var list = document.getElementById("wiz-carte-list");
  if(list && list.children.length === 0){{
    (window.CARTE_CONFIG_INIT || []).forEach(function(c){{
      aggiungiRigaCarta(c.nome, c.cutoff, c.addebito);
    }});
  }}
  var fw = document.getElementById("form-wizard");
  if(fw) fw.addEventListener("submit", preparaCarteJson);
  if(window.WIZARD_AUTO_OPEN){{
    openWizardStep(1);
    openModal("modal-wizard");
  }}
}});
</script>
</body>
</html>"""
    )


CSS = """
:root{
  --text:#0f172a;
  --muted:#64748b;
  --border:#e2e8f0;
  --surface:#ffffff;
  --primary:#2563eb;
  --green:#16a34a;
  --red:#dc2626;
  --amber:#d97706;
  --bg:#f5f7fb;
  --radius:16px;
  --shadow:0 8px 24px rgba(15,23,42,.05);
}
*{box-sizing:border-box}
html{font-size:16px;-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:1rem;line-height:1.5;color:var(--text);background:var(--bg);-webkit-font-smoothing:antialiased}
h1,h2{font-size:1.5rem;line-height:1.2;margin:0;letter-spacing:-.02em}
h3{font-size:1.08rem;margin:0}
p{margin:0}
a{color:var(--primary);text-decoration:none}
button{font:inherit;color:inherit}

.container{width:min(1100px,calc(100% - 32px));margin-inline:auto}
.muted{color:var(--muted)}
.hint{color:var(--muted);font-size:.82rem;font-weight:500}
.positive{color:var(--green)}
.negative{color:var(--red)}
.money{font-variant-numeric:tabular-nums;transition:filter .15s ease,opacity .15s ease}
body.hide-money .money{filter:blur(7px);opacity:.7;user-select:none}

/* Topbar */
.topbar{position:sticky;top:0;z-index:20;background:rgba(245,247,251,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--border)}
.topbar-inner{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;padding:12px 0}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand-mark{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;background:var(--primary);color:#fff;font-size:1.35rem;font-weight:800;box-shadow:0 6px 16px rgba(37,99,235,.25);flex:none}
.brand-sub{color:var(--muted);font-size:.82rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cycle-picker{display:flex;align-items:center;gap:8px;font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.cycle-picker select{font-size:.92rem;font-weight:700;letter-spacing:0;text-transform:none;color:var(--text);background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px 32px 8px 12px;appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 16px) 55%,calc(100% - 11px) 55%;background-size:5px 5px,5px 5px;background-repeat:no-repeat;cursor:pointer}

/* Layout & Cards */
.main{padding:20px 0 24px;display:grid;gap:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}

/* Buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid transparent;border-radius:11px;padding:10px 16px;font-size:.92rem;font-weight:700;cursor:pointer;transition:transform .08s ease,box-shadow .15s ease,background .15s ease;text-decoration:none;white-space:nowrap}
.btn:active{transform:translateY(1px)}
.btn:focus-visible,.icon-btn:focus-visible,.chip:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid rgba(37,99,235,.28);outline-offset:2px}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{background:#1d4ed8}
.btn-green{background:var(--green);color:#fff;box-shadow:0 6px 16px rgba(22,163,74,.18)}
.btn-green:hover{background:#15803d}
.btn-red{background:var(--red);color:#fff;box-shadow:0 6px 16px rgba(220,38,38,.16)}
.btn-red:hover{background:#b91c1c}
.btn-ghost{background:var(--surface);border-color:var(--border);color:var(--text)}
.btn-ghost:hover{background:#f8fafc}

.icon-btn{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:10px;border:1px solid var(--border);background:var(--surface);cursor:pointer;font-size:.95rem;line-height:1;transition:background .15s ease,border-color .15s ease,transform .08s ease}
.icon-btn:hover{background:#f8fafc;border-color:#cbd5e1}
.icon-btn:active{transform:scale(.96)}
.icon-btn.small{width:32px;height:32px;border-radius:9px;font-size:.85rem}
.icon-btn.danger{color:var(--red)}
.icon-btn.danger:hover{background:#fef2f2;border-color:#fecaca}
.icon-btn.paid{color:var(--green);border-color:#bbf7d0;background:#f0fdf4}
.icon-btn.eye{font-size:1.05rem}
.icon-btn.eye.active{background:#eff6ff;border-color:#bfdbfe}

/* Hero & Savings */
.hero{padding:24px 26px 20px}
.hero-grid{display:grid;grid-template-columns:1fr 1fr;gap:26px}
.hero-col{min-width:0}
.hero-col + .hero-col{border-left:1px solid var(--border);padding-left:26px}
.eyebrow{font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}
.hero-value{font-size:2.3rem;font-weight:800;line-height:1.12;letter-spacing:-.035em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stat-row{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px}
.stat{display:flex;flex-direction:column;gap:2px;min-width:0}
.stat-label{font-size:.74rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.stat-value{font-size:.98rem;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.progress-wrap{margin-top:20px}
.progress-track{height:8px;border-radius:999px;background:#e8eef7;overflow:hidden}
.progress-fill{height:100%;border-radius:999px;background:linear-gradient(90deg,var(--primary),#60a5fa);transition:width .3s ease}
.progress-label{display:flex;justify-content:space-between;gap:12px;margin-top:7px;color:var(--muted);font-size:.78rem;font-weight:600}

.savings{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:20px 24px;color:var(--text);border-left:5px solid var(--green);background:linear-gradient(120deg,#f0fdf4 0%,var(--surface) 58%)}
.savings.negative{border-left-color:var(--red);background:linear-gradient(120deg,#fef2f2 0%,var(--surface) 58%)}
.savings-main{min-width:0}
.savings-value{font-size:1.95rem;font-weight:800;letter-spacing:-.03em;line-height:1.15}
.savings-detail{margin-top:6px;color:var(--muted);font-size:.86rem;line-height:1.5}
.savings-badge{flex:none;border-radius:999px;padding:7px 14px;font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}
.savings-badge.positive{background:#dcfce7;color:#166534}
.savings-badge.negative{background:#fee2e2;color:#991b1b}

/* Actions & Filter Chips */
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.actions-note{color:var(--muted);font-size:.84rem;margin-left:2px}
.chipbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:2px 0}
.chip-label{font-size:.74rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-right:4px;flex:none}
.chip{display:inline-flex;align-items:center;border:1px solid var(--border);background:var(--surface);color:var(--muted);border-radius:999px;padding:7px 14px;font-size:.84rem;font-weight:700;white-space:nowrap;flex:none;transition:background .15s ease,color .15s ease,border-color .15s ease}
.chip:hover{background:#f8fafc;color:var(--text)}
.chip.active{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 4px 12px rgba(37,99,235,.22)}

/* Accordions & Day Groups */
.accordion{overflow:hidden}
.accordion-head{width:100%;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 20px;border:0;background:transparent;font-size:1rem;font-weight:800;text-align:left;cursor:pointer}
.accordion-head:hover{background:#fafcff}
.count{display:inline-flex;align-items:center;gap:4px;margin-left:6px;padding:2px 9px;border-radius:999px;background:#eef2f7;color:var(--muted);font-size:.75rem;font-weight:800;vertical-align:middle}
.chev{display:inline-block;color:var(--muted);transition:transform .16s ease;font-size:1rem}
.accordion-head[aria-expanded="true"] .chev{transform:rotate(180deg)}
.accordion-body{display:none;padding:0 18px 16px;border-top:1px solid var(--border)}
.accordion-body.open{display:block}

.day-group{margin-top:14px;border:1px solid var(--border);border-radius:14px;overflow:hidden;background:var(--surface)}
.day-group:first-child{margin-top:14px}
.day-group.today{border-color:#93c5fd;box-shadow:0 4px 14px rgba(37,99,235,.08)}
.day-group.future{border-color:#fde68a}
.day-group-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:10px 14px;background:#f8fafc;border-bottom:1px solid var(--border)}
.day-group.today .day-group-head{background:#eff6ff;border-bottom-color:#dbeafe}
.day-group.future .day-group-head{background:#fffbeb;border-bottom-color:#fef3c7}
.day-group-title{display:flex;align-items:center;gap:8px;font-size:.86rem;font-weight:700;text-transform:capitalize}
.day-group-totals{display:flex;align-items:center;gap:10px;font-size:.82rem;font-weight:800;white-space:nowrap}
.day-group-rows{padding:0 14px}

/* Movement Rows (Desktop & Mobile unified) */
.mov-row{display:grid;grid-template-columns:52px minmax(0,1fr) auto auto;align-items:center;gap:14px;padding:13px 0;border-top:1px solid var(--border)}
.mov-row:first-child{border-top:0}
.mov-date{display:flex;flex-direction:column;align-items:center;justify-content:center;width:46px;height:46px;border-radius:11px;background:#f1f5f9;color:var(--muted);font-size:.72rem;font-weight:700;line-height:1.15;text-transform:uppercase}
.mov-date strong{color:var(--text);font-size:.96rem;font-weight:800;font-variant-numeric:tabular-nums}
.mov-main{min-width:0;display:flex;flex-direction:column;gap:3px}
.mov-title{font-weight:700;font-size:.96rem;color:var(--text);overflow-wrap:anywhere;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.mov-meta{color:var(--muted);font-size:.8rem;overflow-wrap:anywhere}
.mov-amount{font-weight:800;font-size:1.05rem;white-space:nowrap;text-align:right;letter-spacing:-.01em}
.mov-actions{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex-wrap:wrap}

.inline{display:inline-flex;margin:0}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:2px 8px;font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap}
.badge-green{background:#dcfce7;color:#166534}
.badge-amber{background:#fef3c7;color:#92400e}
@keyframes pulse-unpaid{
  0%,100%{background-color:#fffbeb;box-shadow:inset 3px 0 0 #f59e0b}
  50%{background-color:#fef3c7;box-shadow:inset 3px 0 0 #d97706}
}
@keyframes badge-pulse-slow{
  0%,100%{opacity:1;transform:scale(1)}
  50%{opacity:.55;transform:scale(.98)}
}
.mov-row.unpaid-row{animation:pulse-unpaid 3.6s ease-in-out infinite;border-radius:10px;padding-left:10px;padding-right:8px;margin:3px 0}
.badge-unpaid{animation:badge-pulse-slow 3.6s ease-in-out infinite}
.badge-blue{background:#dbeafe;color:#1e40af}
.mini-btn{border:1px solid var(--border);background:var(--surface);color:var(--muted);border-radius:8px;padding:5px 9px;font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.03em;cursor:pointer}
.mini-btn:hover{background:#f8fafc;color:var(--text)}

/* Timeline & Sections */
.section-card{padding:20px 22px 18px}
.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.section-head .muted{font-size:.82rem}
.timeline{position:relative;padding-left:24px;margin-top:4px}
.timeline:before{content:"";position:absolute;left:6px;top:8px;bottom:8px;width:2px;background:var(--border);border-radius:2px}
.tl-day{position:relative;padding:8px 0 14px}
.tl-day:before{content:"";position:absolute;left:-24px;top:13px;width:12px;height:12px;border-radius:50%;background:var(--primary);border:2px solid var(--surface);box-shadow:0 0 0 2px #dbeafe}
.tl-day.today:before{background:var(--red);box-shadow:0 0 0 2px #fee2e2}
.tl-day-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;flex-wrap:wrap}
.tl-day-head strong{font-size:.88rem;text-transform:capitalize}
.tl-totals{display:flex;gap:10px;font-size:.8rem;font-weight:700;white-space:nowrap}
.tl-items{display:grid;gap:6px;margin-top:6px}
.tl-item{display:grid;grid-template-columns:10px minmax(0,1fr) auto;align-items:center;gap:8px;padding:7px 10px;border:1px solid #eef2f7;border-radius:10px;background:#fbfdff}
.tl-desc{font-size:.84rem;overflow-wrap:anywhere}
.tl-amount{font-size:.84rem;font-weight:800;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot.green{background:var(--green)}
.dot.red{background:var(--red)}
.empty{padding:18px 4px;color:var(--muted);font-size:.9rem;text-align:center}
.footer{padding:8px 0 34px;color:var(--muted);font-size:.78rem;text-align:center}

/* Modals */
.modal-overlay{position:fixed;inset:0;z-index:50;display:none;align-items:center;justify-content:center;padding:16px;background:rgba(15,23,42,.5);backdrop-filter:blur(4px)}
.modal-overlay.open{display:flex}
.modal{width:100%;max-width:640px;max-height:92vh;overflow:auto;background:var(--surface);border-radius:20px;box-shadow:0 30px 80px rgba(15,23,42,.28);animation:pop .16s ease-out}
@keyframes pop{from{transform:scale(.97);opacity:.55}to{transform:scale(1);opacity:1}}
.modal-head{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:18px 20px 14px;border-bottom:1px solid var(--border)}
.modal-body{padding:20px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.form-subgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.span2{grid-column:1/-1}
.field{display:flex;flex-direction:column;gap:6px;font-size:.82rem;font-weight:700;color:var(--muted)}
.field .hint{font-weight:500}
.field input,.field select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--text);font-size:1rem;font-weight:500;transition:border-color .15s ease,box-shadow .15s ease}
.field input:hover,.field select:hover{border-color:#cbd5e1}
.field input:focus,.field select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,.12);outline:0}
.field input[type="date"]{font-variant-numeric:tabular-nums}
.check{display:flex;align-items:center;gap:9px;font-size:.88rem;font-weight:600;color:var(--text);cursor:pointer}
.check input{width:18px;height:18px;accent-color:var(--primary)}
.modal-foot{display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap;margin-top:4px;padding-top:16px;border-top:1px solid var(--border)}
.ric-list{display:grid;gap:10px;margin-top:18px;padding-top:16px;border-top:1px solid var(--border)}
.ric-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:12px;background:#fbfdff}
.ric-title{font-weight:700;font-size:.95rem}
.ric-sub{color:var(--muted);font-size:.8rem;margin-top:2px}
body.modal-open{overflow:hidden}

/* Responsive Tablet & Mobile */
@media(max-width:820px){
  .hero-grid{grid-template-columns:1fr;gap:18px}
  .hero-col + .hero-col{border-left:0;border-top:1px solid var(--border);padding-left:0;padding-top:18px}
  .savings{flex-direction:column;align-items:flex-start}
}

@media(max-width:680px){
  .container{width:calc(100% - 24px)}
  .hide-mobile,.actions-note{display:none !important}
  .topbar-inner{padding:10px 0;gap:10px}
  .topbar-actions{width:100%;justify-content:space-between;gap:10px}
  .cycle-picker{flex:1 1 auto;min-width:0}
  .cycle-picker select{width:100%}
  .brand-mark{width:38px;height:38px;font-size:1.2rem}
  h1,h2{font-size:1.25rem}
  .hero{padding:18px 16px}
  .hero-value{font-size:1.95rem}
  .stat-row{grid-template-columns:1fr 1fr;gap:10px}
  .savings{padding:16px}
  .savings-value{font-size:1.7rem}

  /* Barra azioni compatta a 2 colonne su mobile */
  .actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .actions .btn{width:100%;padding:12px}

  /* Chipbar scorrevole orizzontalmente stile app nativa */
  .chipbar{flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:6px;scrollbar-width:none}
  .chipbar::-webkit-scrollbar{display:none}

  /* Riga movimento stile Revolut / Satispay */
  .accordion-body{padding:0 12px 14px}
  .day-group-head{padding:8px 12px}
  .day-group-rows{padding:0 12px}
  .mov-row{grid-template-columns:44px minmax(0,1fr) auto;gap:10px;padding:14px 0;align-items:start}
  .mov-date{width:44px;height:44px;margin-top:2px}
  .mov-title{font-size:.98rem;line-height:1.25}
  .mov-meta{font-size:.78rem;line-height:1.35}
  .mov-amount{font-size:1.05rem;padding-top:2px}
  .mov-actions{grid-column:2/-1;justify-content:flex-start;gap:8px;margin-top:6px}
  .mov-actions .icon-btn.small{width:36px;height:36px}
  .mov-actions .mini-btn{padding:7px 11px;font-size:.72rem}

  /* Bottom sheet modal su smartphone */
  .modal-overlay{padding:0;align-items:flex-end}
  .modal{border-radius:22px 22px 0 0;max-height:90vh}
  .form-grid,.form-subgrid{grid-template-columns:1fr}
  .span2,.modal-foot.span2{grid-column:auto}
  .modal-head{padding:16px}
  .modal-body{padding:16px;padding-bottom:calc(20px + env(safe-area-inset-bottom, 0px))}
  .scan-box{flex-direction:column;align-items:stretch;text-align:center}
  .scan-btn{width:100%;justify-content:center;min-height:44px}
  .mov-main,.mov-title,.mov-meta{min-width:0;overflow-wrap:anywhere;word-break:break-word}
  .mov-amount{white-space:nowrap}
  .stat-card,.hero-col,.card,.accordion{min-width:0;max-width:100%}
  .modal-foot{flex-direction:column-reverse}
  .modal-foot .btn{width:100%;justify-content:center;min-height:44px}
}

/* Schermi Android molto stretti (es. Honor X5c 360px) */
@media(max-width:400px){
  .container{width:calc(100% - 16px)}
  .stat-row{grid-template-columns:1fr;gap:8px}
  .actions{grid-template-columns:1fr;gap:8px}
  .mov-row{grid-template-columns:38px minmax(0,1fr) auto;gap:8px}
  .mov-date{width:38px;height:38px;font-size:.75rem}
  .mov-amount{font-size:.98rem}
  .hero-value{font-size:1.75rem}
}

/* Fix allineamento input iOS/mobile, Honor X5c e blocco finestre */
html,body{max-width:100%;overflow-x:hidden;overscroll-behavior-x:none}
body.modal-open{position:fixed;width:100%;overflow:hidden;overscroll-behavior:none}
*,*::before,*::after{box-sizing:border-box}
.modal-overlay{overflow:hidden;overscroll-behavior:contain;touch-action:none}
.modal{width:100%;max-width:100%;overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;touch-action:pan-y}
.modal-body,.form-grid,.form-subgrid{width:100%;max-width:100%;min-width:0;overflow-x:hidden}
.scan-box{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border:1px dashed var(--border);border-radius:12px;background:var(--bg, #f8fafc);width:100%;max-width:100%}
.scan-status{font-size:.84rem;color:var(--muted);line-height:1.35}
.scan-btn{cursor:pointer;margin:0;white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.field{display:block;width:100%;max-width:100%;min-width:0;font-size:.82rem;font-weight:700;color:var(--muted)}
.field .hint{display:inline;font-weight:500;margin-left:4px}
.field input,.field select{display:block;box-sizing:border-box;width:100%;min-width:0;max-width:100%;height:46px;min-height:46px;margin-top:6px;padding:10px 12px;font-size:16px;line-height:1.25}
.field input[type="date"]{-webkit-appearance:none;appearance:none;display:flex;align-items:center;justify-content:flex-start;text-align:left;background-color:var(--surface)}
.field input[type="date"]::-webkit-date-and-time-value{text-align:left;margin:0;padding:0}

/* Layout compatto e leggibile per Regole attive su mobile (iOS + Honor X5c) */
.ricorrenze-list .mov-row{display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"main amount" "main actions";gap:6px 12px;align-items:center;padding:12px 0}
.ricorrenze-list .mov-main{grid-area:main;min-width:0}
.ricorrenze-list .mov-title{display:flex;flex-wrap:wrap;align-items:center;gap:6px;word-break:normal;overflow-wrap:break-word;line-height:1.3}
.ricorrenze-list .mov-meta{margin-top:4px;word-break:normal;overflow-wrap:break-word;line-height:1.4}
.ricorrenze-list .mov-amount{grid-area:amount;justify-self:end;align-self:start;white-space:nowrap}
.ricorrenze-list .mov-actions{grid-area:actions;grid-column:auto;justify-self:end;margin-top:0}
"""


JS = """
(function(){
  "use strict";

  function aggiornaOcchio(nascosto){
    var bottone = document.getElementById("eye-btn");
    if(!bottone) return;
    bottone.textContent = nascosto ? "🙈" : "👁";
    bottone.title = nascosto ? "Mostra cifre" : "Nascondi cifre";
    bottone.setAttribute("aria-label", bottone.title);
    bottone.classList.toggle("active", nascosto);
  }

  window.toggleMoney = function(){
    var nascosto = document.body.classList.toggle("hide-money");
    try { localStorage.setItem("risparmio-cifre-nascoste", nascosto ? "1" : "0"); } catch(e) {}
    aggiornaOcchio(nascosto);
  };

  window.toggleCollapse = function(id){
    var corpo = document.getElementById(id);
    if(!corpo) return;
    var aperto = corpo.classList.toggle("open");
    var testa = document.querySelector('[data-collapse="' + id + '"]');
    if(testa) testa.setAttribute("aria-expanded", aperto ? "true" : "false");
  };

  window.openModal = function(id){
    var overlay = document.getElementById(id);
    if(!overlay) return;
    overlay.classList.add("open");
    document.body.classList.add("modal-open");
    var campo = overlay.querySelector("input:not([type=hidden]), select, textarea");
    if(campo) window.setTimeout(function(){ campo.focus(); }, 40);
  };

  window.closeModal = function(id){
    var overlay = document.getElementById(id);
    if(!overlay) return;
    overlay.classList.remove("open");
    if(!document.querySelector(".modal-overlay.open")){
      document.body.classList.remove("modal-open");
    }
  };

  window.formatImporto = function(el){
    if(!el || !el.value) return;
    var valore = String(el.value).trim().replace(/€/g, "").replace(/\\s/g, "");
    if(valore.indexOf(",") > -1 && valore.indexOf(".") > -1){
      if(valore.lastIndexOf(",") > valore.lastIndexOf(".")){
        valore = valore.replace(/\\./g, "").replace(",", ".");
      } else {
        valore = valore.replace(/,/g, "");
      }
    } else if(valore.indexOf(",") > -1){
      valore = valore.replace(",", ".");
    }
    var numero = parseFloat(valore);
    if(!isFinite(numero)){ el.value = ""; return; }
    el.value = numero.toFixed(2);
  };
  window["format-importo"] = window.formatImporto;

  function setValore(id, valore){
    var el = document.getElementById(id);
    if(el) el.value = valore == null ? "" : valore;
  }

  window.toggleEditCategoria = function(){
    var sel = document.getElementById("edit-categoria");
    var entrata = sel && sel.value === "entrata";
    var titolo = document.getElementById("titolo-edit");
    if(titolo) titolo.textContent = entrata ? "Modifica entrata" : "Modifica spesa";
    var bloccoEntrata = document.getElementById("edit-entrata-fields");
    var bloccoSpesa = document.getElementById("edit-spesa-fields");
    if(bloccoEntrata) bloccoEntrata.style.display = entrata ? "" : "none";
    if(bloccoSpesa) bloccoSpesa.style.display = entrata ? "none" : "";
  };

  window.openEdit = function(bottone){
    var dati;
    try { dati = JSON.parse(bottone.dataset.mov); } catch(e) { return; }
    var form = document.getElementById("edit-form");
    if(form) form.action = "/update-movimento/" + encodeURIComponent(dati.tipo) + "/" + encodeURIComponent(dati.id);
    setValore("edit-categoria", dati.tipo === "entrata" ? "entrata" : "spesa");
    setValore("edit-descrizione", dati.descrizione || "");
    setValore("edit-importo", Number(dati.importo || 0).toFixed(2));
    setValore("edit-data", dati.data || "");
    setValore("edit-provenienza", dati.provenienza || "");
    setValore("edit-data-acquisto", dati.data_acquisto || "");
    setValore("edit-metodo", dati.metodo || "Contanti");
    setValore("edit-tipo-spesa", dati.tipo_spesa || "pagamento immediato");
    var pagata = document.getElementById("edit-pagata");
    if(pagata) pagata.checked = !!dati.pagata;
    toggleEditCategoria();
    aggiornaCampiCartaEdit();
    openModal("modal-edit");
  };

  window.aggiornaCampiCartaSpesa = function(){
    var sel = document.getElementById("spesa-metodo");
    var isCC = sel && (window.CARTE_CREDITO || []).indexOf(sel.value) !== -1;
    var wData = document.getElementById("spesa-wrap-data");
    var wAcq = document.getElementById("spesa-wrap-acq");
    var wPag = document.getElementById("spesa-wrap-pagata");
    var inData = document.getElementById("spesa-data");
    var inAcq = document.getElementById("spesa-data-acquisto");
    if(wData) wData.style.display = isCC ? "none" : "";
    if(wAcq) wAcq.style.display = isCC ? "" : "none";
    if(wPag) wPag.style.display = isCC ? "none" : "";
    if(inData) inData.required = !isCC;
    if(inAcq){ inAcq.required = isCC; if(isCC && !inAcq.value && inData) inAcq.value = inData.value; }
    var cbPag = wPag ? wPag.querySelector('input[name="pagata"]') : null;
    if(cbPag && sel){ cbPag.checked = (sel.value !== "Da valutare"); }
  };

  window.aggiornaCampiCartaEdit = function(){
    var cat = document.getElementById("edit-categoria");
    var sel = document.getElementById("edit-metodo");
    var isSpesaCC = (!cat || cat.value === "spesa") && sel && (window.CARTE_CREDITO || []).indexOf(sel.value) !== -1;
    var inData = document.getElementById("edit-data");
    var fData = inData ? inData.closest(".field") : null;
    var wAcq = document.getElementById("edit-wrap-acq");
    var wPag = document.getElementById("edit-wrap-pagata");
    var inAcq = document.getElementById("edit-data-acquisto");
    if(fData) fData.style.display = isSpesaCC ? "none" : "";
    if(wAcq) wAcq.style.display = isSpesaCC ? "" : "none";
    if(wPag) wPag.style.display = "";
    if(inData) inData.required = !isSpesaCC;
    if(inAcq){ inAcq.required = isSpesaCC; if(isSpesaCC && !inAcq.value && inData) inAcq.value = inData.value; }
  };

  window.resetFormRicorrenza = function(){
    var form = document.getElementById("form-ricorrenza");
    if(!form) return;
    form.action = "/add-ricorrenza";
    form.reset();
    var btnSub = document.getElementById("btn-submit-ric");
    if(btnSub) btnSub.textContent = "Attiva ricorrenza automatica";
    var btnCan = document.getElementById("btn-cancel-edit-ric");
    if(btnCan) btnCan.style.display = "none";
    var hint = document.getElementById("ric-form-hint");
    if(hint) hint.textContent = "Imposta il numero di rate oppure la data dell'ultima rata: il sistema genererà i movimenti fino alla scadenza indicata.";
  };

  window.openEditRicorrenza = function(bottone){
    var dati;
    try { dati = JSON.parse(bottone.dataset.ric); } catch(e) { return; }
    var form = document.getElementById("form-ricorrenza");
    if(!form) return;
    form.action = "/update-ricorrenza/" + encodeURIComponent(dati.id);
    setValore("ric-categoria", dati.categoria || "spesa");
    setValore("ric-frequenza", dati.frequenza || "mensile");
    setValore("ric-descrizione", dati.descrizione || "");
    setValore("ric-importo", Number(dati.importo || 0).toFixed(2));
    setValore("ric-data-inizio", dati.data_inizio || "");
    setValore("ric-metodo", dati.metodo || "SDD");
    setValore("ric-provenienza", dati.provenienza || "");
    setValore("ric-num-rate", dati.num_rate || "");
    setValore("ric-data-fine", dati.data_fine || "");
    var chkPag = document.getElementById("ric-pagata");
    if(chkPag) chkPag.checked = !!dati.pagata;
    var btnSub = document.getElementById("btn-submit-ric");
    if(btnSub) btnSub.textContent = "Salva modifiche ricorrenza";
    var btnCan = document.getElementById("btn-cancel-edit-ric");
    if(btnCan) btnCan.style.display = "inline-flex";
    var hint = document.getElementById("ric-form-hint");
    if(hint) hint.textContent = "Stai modificando una regola attiva: salvando verranno aggiornate anche le rate future non ancora pagate.";
    var modalBody = form.closest(".modal-body");
    if(modalBody) modalBody.scrollTop = 0;
  };

  window.openRicorrenzaFromMov = function(bottone){
    resetFormRicorrenza();
    var dati;
    try { dati = JSON.parse(bottone.dataset.mov); } catch(e) { return; }
    setValore("ric-categoria", dati.tipo === "entrata" ? "entrata" : "spesa");
    setValore("ric-frequenza", "mensile");
    setValore("ric-descrizione", dati.descrizione || "");
    setValore("ric-importo", Number(dati.importo || 0).toFixed(2));
    setValore("ric-data-inizio", dati.data || "");
    setValore("ric-metodo", dati.metodo || "SDD");
    setValore("ric-provenienza", dati.provenienza || "");
    openModal("modal-ricorrenze");
  };

  function escHtml(v){
    return String(v == null ? "" : v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  window.resetRicercaMovimenti = function(){
    setValore("cerca-q",""); setValore("cerca-da",""); setValore("cerca-a","");
    var r = document.getElementById("cerca-riepilogo"), b = document.getElementById("cerca-risultati");
    if(r) r.textContent = "Inserisci un nome e/o una data e premi Cerca.";
    if(b) b.innerHTML = "";
  };
  window.eseguiRicercaMovimenti = async function(ev){
    if(ev) ev.preventDefault();
    var q = (document.getElementById("cerca-q")||{}).value||"";
    var da = (document.getElementById("cerca-da")||{}).value||"";
    var a = (document.getElementById("cerca-a")||{}).value||"";
    var r = document.getElementById("cerca-riepilogo"), b = document.getElementById("cerca-risultati");
    if(!q.trim() && !da && !a){ if(r) r.textContent = "Inserisci almeno un nome o una data."; return; }
    if(r) r.textContent = "⏳ Ricerca in corso...";
    try{
      var p = new URLSearchParams();
      if(q.trim()) p.set("q", q.trim());
      if(da) p.set("data_da", da);
      if(a) p.set("data_a", a);
      var res = await fetch("/api/cerca?" + p.toString());
      var d = await res.json();
      if(!res.ok) throw new Error(d.detail || "Errore ricerca");
      var items = d.risultati || [];
      if(!items.length){
        if(r) r.textContent = "Nessun movimento trovato.";
        if(b) b.innerHTML = '<div class="empty">Nessun risultato trovato.</div>';
        return;
      }
      if(r) r.innerHTML = 'Trovati <strong>'+items.length+'</strong> movimenti · Spese: <strong class="money negative">-'+escHtml(d.tot_spese_fmt)+'</strong> · Entrate: <strong class="money positive">+'+escHtml(d.tot_entrate_fmt)+'</strong>';
      b.innerHTML = items.map(function(it){
        var ent = it.categoria === "entrata";
        var bg = ent ? '<span class="badge badge-green">entrata</span>' : (it.pagata ? '<span class="badge badge-green">pagata</span>' : '<span class="badge badge-amber badge-unpaid">da pagare</span>');
        return '<a href="/?ciclo='+encodeURIComponent(it.ciclo_key)+'" class="mov-row" style="text-decoration:none;color:inherit;padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:#fff;display:grid;grid-template-columns:56px minmax(0,1fr) auto;gap:10px;align-items:center">'
          + '<div class="mov-date"><strong>'+escHtml(it.data_breve)+'</strong><span>'+escHtml(it.anno)+'</span></div>'
          + '<div class="mov-main"><div class="mov-title">'+escHtml(it.descrizione)+' '+bg+'</div>'
          + '<div class="mov-meta">'+escHtml(it.meta)+' · Ciclo '+escHtml(it.ciclo_label)+'</div></div>'
          + '<div class="mov-amount money '+(ent?"positive":"negative")+'">'+(ent?"+":"-")+escHtml(it.importo_fmt)+'</div></a>';
      }).join("");
    }catch(e){ if(r) r.textContent = "❌ " + e.message; }
  };
  document.addEventListener("DOMContentLoaded", function(){
    var nascosto = false;
    try { nascosto = localStorage.getItem("risparmio-cifre-nascoste") === "1"; } catch(e) {}
    if(nascosto) document.body.classList.add("hide-money");
    aggiornaOcchio(nascosto);
  });

  document.addEventListener("keydown", function(evento){
    if(evento.key === "Escape"){
      var aperti = document.querySelectorAll(".modal-overlay.open");
      for(var i = 0; i < aperti.length; i++) closeModal(aperti[i].id);
    }
  });

  document.addEventListener("click", function(evento){
    if(evento.target && evento.target.classList && evento.target.classList.contains("modal-overlay")){
      closeModal(evento.target.id);
    }
  });
})();
"""


# ---------------------------------------------------------------------------
# Calcoli e redirect
# ---------------------------------------------------------------------------


def calcola_riporto(db: Session, inizio: date) -> float:
    """Saldo cumulativo storico prima dell'inizio del ciclo selezionato."""
    if inizio <= DATA_INIZIO_CONTABILITA:
        return 0.0
    entrate = (
        db.query(func.coalesce(func.sum(Entrata.importo), 0.0))
        .filter(
            Entrata.data >= DATA_INIZIO_CONTABILITA,
            Entrata.data < inizio,
        )
        .scalar()
        or 0.0
    )
    spese = (
        db.query(func.coalesce(func.sum(Spesa.importo), 0.0))
        .filter(
            Spesa.data >= DATA_INIZIO_CONTABILITA,
            Spesa.data < inizio,
        )
        .scalar()
        or 0.0
    )
    return round(float(entrate) - float(spese), 2)


def _back(
    ciclo: Optional[str],
    vista_metodo: Optional[str],
    fallback: date,
) -> RedirectResponse:
    inizio = parse_chiave_ciclo(ciclo) or inizio_ciclo(fallback)
    parametri = {"ciclo": chiave_ciclo(inizio)}
    if vista_metodo in METODI:
        parametri["metodo"] = vista_metodo
    parametri["ok"] = "1"
    return RedirectResponse(url="/?" + urlencode(parametri), status_code=303)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


def _render_righe_ricorrenze(db: Session, ciclo_key: str, vista_metodo: Optional[str]) -> str:
    regole = (
        db.query(Ricorrenza)
        .filter(Ricorrenza.attiva.is_(True))
        .order_by(Ricorrenza.categoria, Ricorrenza.giorno_scadenza, Ricorrenza.id)
        .all()
    )
    if not regole:
        return '<div class="empty">Nessuna ricorrenza automatica attiva. Usa "↻" su un movimento o il modulo qui sopra.</div>'
    nascosti = hidden_vista(ciclo_key, vista_metodo)
    righe = []
    for r in regole:
        quando = (
            f"Ogni {r.giorno_scadenza} {MESI[(r.mese_scadenza or r.data_inizio.month) - 1]} (annuale)"
            if r.frequenza == "annuale"
            else f"Ogni {r.giorno_scadenza} del mese (mensile)"
        )
        df_eff = _calcola_data_fine_ricorrenza(
            r.data_inizio, r.frequenza, r.giorno_scadenza, r.mese_scadenza, r.num_rate, r.data_fine
        )
        if r.num_rate and df_eff:
            quando += f" · {r.num_rate} rate (fine {df_eff.day} {MESI[df_eff.month - 1]} {df_eff.year})"
        elif df_eff:
            quando += f" · fino al {df_eff.day} {MESI[df_eff.month - 1]} {df_eff.year}"
        dettaglio = r.provenienza or "Entrata" if r.categoria == "entrata" else r.metodo
        cls = "positive" if r.categoria == "entrata" else "negative"
        segno = "+" if r.categoria == "entrata" else "-"
        ric_payload = {
            "id": r.id,
            "categoria": r.categoria,
            "frequenza": r.frequenza,
            "descrizione": r.descrizione or "",
            "importo": round(float(r.importo or 0), 2),
            "data_inizio": r.data_inizio.isoformat() if r.data_inizio else "",
            "metodo": r.metodo or "SDD",
            "provenienza": r.provenienza or "",
            "num_rate": r.num_rate if r.num_rate else "",
            "data_fine": r.data_fine.isoformat() if r.data_fine else "",
            "pagata": bool(getattr(r, "pagata", False)),
        }
        righe.append(
            f'<div class="mov-row" >'
            f'<div class="mov-main"><div class="mov-title">{esc(r.descrizione)} '
            f'<span class="badge {"badge-green" if r.categoria == "entrata" else "badge-blue"}">{esc(r.frequenza)}</span>{" <span class=\"badge badge-green\">già pagata</span>" if (r.categoria != "entrata" and getattr(r, "pagata", False)) else ""}</div>'
            f'<div class="mov-meta">{esc(quando)} · {esc(dettaglio)} · dal {data_italiana(r.data_inizio)}</div></div>'
            f'<div class="mov-amount money {cls}">{segno}{fmt_money(r.importo)}</div>'
            f'<div class="mov-actions">'
            f'<button type="button" class="icon-btn small" data-ric=\'{json_attr(ric_payload)}\' onclick="openEditRicorrenza(this)" title="Modifica ricorrenza">✎</button>'
            f'<form method="post" action="/delete-ricorrenza/{r.id}" class="inline" onsubmit="return confirm(\'Disattivare questa ricorrenza e rimuovere le occorrenze future non ancora pagate?\');">{nascosti}<button type="submit" class="icon-btn small danger" title="Elimina ricorrenza">🗑</button></form>'
            f'</div>'
            f'</div>'
        )
    return "".join(righe)



def _build_app_icon_png(size: int) -> bytes:
    """Genera un PNG ad alta definizione con antialiasing 4x4 (SDF vettoriale) per iOS e Android."""
    import math, struct, zlib

    w = h = size
    cx = cy = (size - 1) / 2.0
    # Raggi normalizzati rispetto alla dimensione dell'icona
    ring_r = size * 0.355
    ring_half_w = size * 0.013

    # Parametri vettoriali del simbolo € centrato
    e_cx = cx + size * 0.025
    e_cy = cy
    e_rx = size * 0.175
    e_ry = size * 0.215
    e_thick = size * 0.044
    # Apertura a destra della C dell'euro (in radianti, ~42 gradi)
    open_cos = math.cos(math.radians(42))

    # Due barrette orizzontali arrotondate dell'euro
    bar_x0 = cx - size * 0.205
    bar_x1 = cx + size * 0.115
    bar1_y = cy - size * 0.046
    bar2_y = cy + size * 0.046
    bar_half_h = size * 0.021

    # Sub-pixel offsets 4x4 per antialiasing liscio su ogni bordo curvo
    sub = (-0.375, -0.125, 0.125, 0.375)

    def sample_alpha(px: float, py: float) -> tuple[float, float]:
        """Restituisce (alpha_anello, alpha_euro) in [0.0, 1.0]."""
        # 1. Anello sottile decorativo
        dx0, dy0 = px - cx, py - cy
        d_ring = abs(math.hypot(dx0, dy0) - ring_r)
        ring_a = 1.0 if d_ring <= ring_half_w else 0.0

        # 2. Corpo curvo della C del simbolo €
        ex = (px - e_cx) / e_rx
        ey = (py - e_cy) / e_ry
        dist_ell = math.hypot(ex, ey)
        # Spessore normalizzato
        norm_thick = e_thick / ((e_rx + e_ry) * 0.5)
        in_ring_e = abs(dist_ell - 1.0) <= (norm_thick * 0.5)
        if in_ring_e and dist_ell > 1e-6:
            # Taglio apertura a destra (ex / dist_ell > open_cos)
            if (ex / dist_ell) > open_cos:
                in_ring_e = False

        # 3. Due barrette orizzontali con estremità arrotondate (capsule SDF)
        in_bars = False
        for by in (bar1_y, bar2_y):
            clamped_x = min(max(px, bar_x0), bar_x1)
            if math.hypot(px - clamped_x, py - by) <= bar_half_h:
                in_bars = True
                break

        euro_a = 1.0 if (in_ring_e or in_bars) else 0.0
        return ring_a, euro_a

    rows = bytearray()
    for y in range(h):
        rows.append(0)
        t = y / (h - 1)
        # Gradiente morbido #3b82f6 -> #1d4ed8
        bg_r = 59.0 * (1.0 - t) + 29.0 * t
        bg_g = 130.0 * (1.0 - t) + 78.0 * t
        bg_b = 246.0 * (1.0 - t) + 216.0 * t

        for x in range(w):
            # Fast-path per pixel lontani da anello ed euro (sfondo puro)
            dist_center = math.hypot(x - cx, y - cy)
            if dist_center > ring_r + ring_half_w + 2.0:
                rows.extend((int(bg_r), int(bg_g), int(bg_b)))
                continue

            r_acc = 0.0
            e_acc = 0.0
            for sy in sub:
                py = y + sy
                for sx in sub:
                    ra, ea = sample_alpha(x + sx, py)
                    r_acc += ra
                    e_acc += ea

            ring_cov = (r_acc / 16.0) * 0.24
            euro_cov = e_acc / 16.0

            # Composizione alpha: sfondo -> anello semitrasparente -> euro bianco pieno
            r = bg_r * (1.0 - ring_cov) + 255.0 * ring_cov
            g = bg_g * (1.0 - ring_cov) + 255.0 * ring_cov
            b = bg_b * (1.0 - ring_cov) + 255.0 * ring_cov

            r = r * (1.0 - euro_cov) + 255.0 * euro_cov
            g = g * (1.0 - euro_cov) + 255.0 * euro_cov
            b = b * (1.0 - euro_cov) + 255.0 * euro_cov

            rows.extend((int(round(r)), int(round(g)), int(round(b))))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack("!IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b"")


_ICON_180_PNG = _build_app_icon_png(180)
_ICON_192_PNG = _build_app_icon_png(192)
_ICON_512_PNG = _build_app_icon_png(512)


@app.get("/icon.svg")
def icon_svg() -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180">'
        '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#1d4ed8"/>'
        '</linearGradient></defs>'
        '<rect width="180" height="180" rx="40" fill="url(#g)"/>'
        '<circle cx="90" cy="90" r="62" fill="none" stroke="rgba(255,255,255,0.22)" stroke-width="4"/>'
        '<text x="90" y="116" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" '
        'font-size="94" font-weight="800" fill="#ffffff">€</text>'
        '</svg>'
    )
    return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/apple-touch-icon.png")
@app.get("/apple-touch-icon-precomposed.png")
@app.get("/favicon.ico")
def apple_touch_icon() -> Response:
    return Response(content=_ICON_180_PNG, media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/icon-192.png?v=2")
def icon_192() -> Response:
    return Response(content=_ICON_192_PNG, media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/icon-512.png?v=2")
def icon_512() -> Response:
    return Response(content=_ICON_512_PNG, media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/manifest.webmanifest")
def web_manifest() -> JSONResponse:
    return JSONResponse(
        content={
            "name": "Bilancio familiare",
            "short_name": "Bilancio",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#f8fafc",
            "theme_color": "#2563eb",
            "icons": [
                {"src": "/icon-192.png?v=2", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
                {"src": "/icon-512.png?v=2", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
            ],
        },
        media_type="application/manifest+json",
    )



@app.post("/save-wizard")
def save_wizard(
    request: Request,
    giorno_inizio_ciclo: int = Form(1),
    data_inizio_contabilita: str = Form(""),
    carte_json: str = Form("[]"),
    pac_percentuale: float = Form(10.0),
    pac_fisso: float = Form(0.0),
    cuscinetto_percentuale: float = Form(0.0),
    cuscinetto_fisso: float = Form(0.0),
    nuovo_username: str = Form(""),
    nuova_password: str = Form(""),
    ciclo: Optional[str] = Form(None),
    metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    g = min(28, max(1, int(giorno_inizio_ciclo)))
    try:
        d_start = date.fromisoformat(data_inizio_contabilita.strip()[:10])
    except ValueError:
        d_start = date.today().replace(day=g)

    try:
        raw_cards = json.loads(carte_json)
        if not isinstance(raw_cards, list):
            raw_cards = []
    except Exception:
        raw_cards = []

    carte_pulite = []
    visti = set()
    for c in raw_cards:
        if not isinstance(c, dict):
            continue
        nome = str(c.get("nome", "")).strip()
        if not nome or nome in visti or nome in METODI_BASE:
            continue
        visti.add(nome)
        cutoff = min(28, max(1, int(c.get("cutoff", 15))))
        addebito = min(28, max(0, int(c.get("addebito", 0))))
        carte_pulite.append({"nome": nome, "cutoff": cutoff, "addebito": addebito})

    updates = {
        "giorno_inizio_ciclo": str(g),
        "data_inizio_contabilita": d_start.isoformat(),
        "carte_credito_json": json.dumps(carte_pulite, ensure_ascii=False),
        "pac_percentuale": str(round(max(0.0, min(100.0, pac_percentuale)) / 100.0, 4)),
        "pac_fisso": str(round(max(0.0, pac_fisso), 2)),
        "cuscinetto_percentuale": str(round(max(0.0, min(100.0, cuscinetto_percentuale)) / 100.0, 4)),
        "cuscinetto_fisso": str(round(max(0.0, cuscinetto_fisso), 2)),
        "wizard_completato": "1",
    }

    u_curr, p_curr = _get_auth_credentials()
    new_u = nuovo_username.strip() if len(nuovo_username.strip()) >= 3 else u_curr
    new_p_secret = p_curr
    aggiorna_cookie = False

    if new_u and new_u != u_curr:
        updates["auth_user"] = new_u
        aggiorna_cookie = True
    if len(nuova_password) >= 4:
        new_p_secret = _hash_password(nuova_password)
        updates["auth_pass_hash"] = new_p_secret
        if new_u:
            updates["auth_user"] = new_u
        aggiorna_cookie = True

    for k, v in updates.items():
        row = db.get(Config, k)
        if row is None:
            db.add(Config(chiave=k, valore=v))
        else:
            row.valore = v
    db.commit()
    ricarica_impostazioni_globali(db)

    spese_cc = db.query(Spesa).filter(Spesa.metodo.in_(list(CARTE_ATTIVE_MAP.keys()))).all()
    for s in spese_cc:
        da_acq = s.data_acquisto or s.data
        s.data_acquisto = da_acq
        s.data = calcola_addebito_carta(s.metodo, da_acq)
    db.commit()

    params = {"ok": "1"}
    if metodo:
        params["metodo"] = metodo
    resp = RedirectResponse(url="/?" + urlencode(params), status_code=303)
    if aggiorna_cookie and new_u and new_p_secret:
        resp.set_cookie(
            key=COOKIE_NAME,
            value=_sign_session(new_u, new_p_secret),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=_is_https(request),
        )
    return resp

@app.get("/", response_class=HTMLResponse)
def dashboard(
    ciclo: Optional[str] = None,
    metodo: Optional[str] = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    cfg_wiz = ricarica_impostazioni_globali(db)
    oggi = oggi_italia()
    sincronizza_ricorrenze(db)
    spese_cutoff = (
        db.query(Spesa)
        .filter(
            Spesa.metodo != "Da valutare",
            Spesa.pagata.is_(False), Spesa.metodo.in_(list(CARTE_ATTIVE_MAP.keys())),
            Spesa.data <= oggi,
        )
        .all()
    )
    if spese_cutoff:
        for s_cut in spese_cutoff:
            s_cut.pagata = True
        db.commit()
    cicli_disponibili = elenco_cicli(db)
    ciclo_corrente = inizio_ciclo(oggi)
    if ciclo_corrente not in cicli_disponibili:
        cicli_disponibili = sorted(set(cicli_disponibili + [ciclo_corrente]))
    inizio = parse_chiave_ciclo(ciclo) or ciclo_corrente
    if cicli_disponibili:
        if inizio < cicli_disponibili[0]:
            inizio = cicli_disponibili[0]
        elif inizio > cicli_disponibili[-1]:
            inizio = cicli_disponibili[-1]
    fine = fine_ciclo(inizio)
    if metodo not in METODI:
        metodo = None

    entrate = (
        db.query(Entrata)
        .filter(Entrata.data >= inizio, Entrata.data <= fine)
        .order_by(Entrata.data, Entrata.id)
        .all()
    )
    spese = (
        db.query(Spesa)
        .filter(Spesa.data >= inizio, Spesa.data <= fine)
        .order_by(Spesa.data, Spesa.id)
        .all()
    )
    spese_visibili = [
        spesa for spesa in spese
        if metodo is None or spesa.metodo == metodo
    ]

    entrate_totali = round(sum(float(e.importo or 0) for e in entrate), 2)
    uscite_totali = round(sum(float(s.importo or 0) for s in spese), 2)
    spese_fisse_display = round(
        sum(float(s.importo or 0) for s in spese if s.tipo != TIPO_IMMEDIATO), 2
    )
    spese_variabili_display = round(uscite_totali - spese_fisse_display, 2)

    tot_entrate = round(
        sum(float(e.importo or 0) for e in entrate if e.data <= oggi), 2
    )
    entrate_previste = round(
        sum(float(e.importo or 0) for e in entrate if e.data > oggi), 2
    )
    spese_fisse_calc = round(
        sum(
            float(s.importo or 0)
            for s in spese
            if s.tipo != TIPO_IMMEDIATO and s.data <= oggi
        ),
        2,
    )
    spese_discrezionali_fatte = round(
        sum(
            float(s.importo or 0)
            for s in spese
            if s.tipo == TIPO_IMMEDIATO and s.data <= oggi
        ),
        2,
    )
    spese_previste = round(
        sum(
            float(s.importo or 0)
            for s in spese
            if s.tipo == TIPO_IMMEDIATO and s.data > oggi
        ),
        2,
    )

    giorni_totali = (fine - inizio).days + 1
    if oggi > fine:
        giorni_rimanenti = 0
        giorni_trascorsi = giorni_totali
    elif oggi < inizio:
        giorni_rimanenti = giorni_totali
        giorni_trascorsi = 0
    else:
        giorni_rimanenti = (fine - oggi).days + 1
        giorni_trascorsi = (oggi - inizio).days + 1
    progress = (
        max(0, min(100, round(giorni_trascorsi / giorni_totali * 100)))
        if giorni_totali > 0
        else 0
    )

    media_discrezionali = (
        round(spese_discrezionali_fatte / giorni_trascorsi, 2)
        if giorni_trascorsi > 0
        else 0.0
    )
    riporto = calcola_riporto(db, inizio)
    pac_perc = config_float(db, "pac_percentuale", 0.10)
    cuscinetto_perc = config_float(db, "cuscinetto_percentuale", 0.0)
    pac_fisso = config_float(db, "pac_fisso", 0.0)
    cuscinetto_fisso = config_float(db, "cuscinetto_fisso", 0.0)

    ciclo_futuro = oggi < inizio
    netto_previsto_futuro = round(entrate_totali - uscite_totali, 2)
    if ciclo_futuro:
        # Sui cicli futuri mostra subito la pianificazione completa del mese (entrate previste - spese già programmate)
        risultato = calcola_budget(
            riporto_ciclo_prec=0.0,
            tot_entrate_ciclo=entrate_totali,
            spese_fisse_ciclo_tot=spese_fisse_display,
            spese_discrezionali_fatte=spese_variabili_display,
            giorni_rimanenti=giorni_totali,
            pac_percentuale=pac_perc,
            cuscinetto_percentuale=cuscinetto_perc,
            entrate_previste_fino_fine=0.0,
            spese_previste_fino_fine=0.0,
            spese_discrezionali_medie_giornaliere=0.0,
            pac_fisso=pac_fisso,
            cuscinetto_fisso=cuscinetto_fisso,
        )
    else:
        # Nel ciclo corrente: zero riporto nel budget, spese fisse del mese già scalate subito
        risultato = calcola_budget(
            riporto_ciclo_prec=0.0,
            tot_entrate_ciclo=tot_entrate,
            spese_fisse_ciclo_tot=spese_fisse_display,
            spese_discrezionali_fatte=spese_discrezionali_fatte,
            giorni_rimanenti=giorni_rimanenti,
            pac_percentuale=pac_perc,
            cuscinetto_percentuale=cuscinetto_perc,
            entrate_previste_fino_fine=entrate_previste,
            spese_previste_fino_fine=spese_previste,
            spese_discrezionali_medie_giornaliere=0.0,
            pac_fisso=pac_fisso,
            cuscinetto_fisso=cuscinetto_fisso,
        )

    cicli = sorted(set(cicli_disponibili + [inizio]))
    idx_corrente = cicli.index(inizio)
    prev_ciclo = cicli[idx_corrente - 1] if idx_corrente > 0 else None
    next_ciclo = cicli[idx_corrente + 1] if idx_corrente < len(cicli) - 1 else None

    ora_roma = adesso_italia()
    if inizio == ciclo_corrente:
        giorno_ciclo_label = f"Giorno {giorni_trascorsi} di {giorni_totali} del ciclo"
    elif oggi < inizio:
        giorno_ciclo_label = f"Ciclo futuro (inizia tra {(inizio - oggi).days}g)"
    else:
        giorno_ciclo_label = "Ciclo concluso"
    roma_now_label = f"{nome_giorno(oggi).capitalize()} {data_italiana(oggi)}, {ora_roma.strftime('%H:%M')}"

    ctx = {
        "oggi": oggi,
        "roma_now_label": roma_now_label,
        "giorno_ciclo_label": giorno_ciclo_label,
        "start": inizio,
        "end": fine,
        "ciclo_key": chiave_ciclo(inizio),
        "etichetta": etichetta_ciclo(inizio),
        "range_label": f"{data_italiana(inizio)} → {data_italiana(fine)}",
        "cicli": cicli,
        "is_ciclo_corrente": (inizio == ciclo_corrente),
        "prev_ciclo_url": (
            "/?" + urlencode({"ciclo": chiave_ciclo(prev_ciclo), **({"metodo": metodo} if metodo else {})})
            if prev_ciclo
            else None
        ),
        "prev_etichetta": etichetta_ciclo(prev_ciclo) if prev_ciclo else "",
        "next_ciclo_url": (
            "/?" + urlencode({"ciclo": chiave_ciclo(next_ciclo), **({"metodo": metodo} if metodo else {})})
            if next_ciclo
            else None
        ),
        "next_etichetta": etichetta_ciclo(next_ciclo) if next_ciclo else "",
        "metodo": metodo,
        "entrate": entrate,
        "spese": spese,
        "spese_visibili": spese_visibili,
        "entrate_totali": entrate_totali,
        "uscite_totali": uscite_totali,
        "spese_fisse_display": spese_fisse_display,
        "spese_variabili_display": spese_variabili_display,
        "entrate_previste": entrate_previste,
        "spese_previste": spese_previste,
        "media_discr": media_discrezionali,
        "riporto": riporto,
        "prelievi_salvadanaio": round(sum(float(e.importo or 0) for e in entrate if (e.provenienza or "").strip() == "Salvadanaio"), 2),
        "risultato": risultato,
        "giorni_totali": giorni_totali,
        "giorni_trascorsi": giorni_trascorsi,
        "giorni_rimanenti": giorni_rimanenti,
        "progress": progress,
        "netto_previsto_futuro": netto_previsto_futuro,
        "pac_perc": pac_perc,
        "cuscinetto_perc": cuscinetto_perc,
        "pac_fisso": pac_fisso,
        "cuscinetto_fisso": cuscinetto_fisso,
        "giorno_inizio_ciclo": GIORNO_INIZIO_CICLO,
        "data_inizio_contabilita": DATA_INIZIO_CONTABILITA.isoformat(),
        "carte_credito": list(CARTE_ATTIVE_MAP.values()),
        "wizard_completato": cfg_wiz.get("wizard_completato", True),
        "auth_user": cfg_wiz.get("auth_user", ""),
        "pac_fisso": pac_fisso,
        "cuscinetto_fisso": cuscinetto_fisso,
        "ricorrenze": db.query(Ricorrenza).filter(Ricorrenza.attiva.is_(True)).order_by(Ricorrenza.categoria, Ricorrenza.giorno_scadenza).all(),
        "righe_ricorrenze": _render_righe_ricorrenze(db, chiave_ciclo(inizio), metodo),
    }
    return HTMLResponse(render_dashboard(ctx))



@app.get("/api/cerca")
def api_cerca_movimenti(q: Optional[str] = None, data_da: Optional[str] = None, data_a: Optional[str] = None, db: Session = Depends(get_db)) -> JSONResponse:
    testo = (q or "").strip().lower()
    d_da, d_a = parse_date(data_da, None), parse_date(data_a, None)
    qs, qe = db.query(Spesa), db.query(Entrata)
    if d_da:
        qs, qe = qs.filter(Spesa.data >= d_da), qe.filter(Entrata.data >= d_da)
    if d_a:
        qs, qe = qs.filter(Spesa.data <= d_a), qe.filter(Entrata.data <= d_a)
    risultati, tot_s, tot_e = [], 0.0, 0.0
    for item in qs.order_by(Spesa.data.desc(), Spesa.id.desc()).all():
        if testo and testo not in f"{item.descrizione or ''} {item.metodo or ''} {item.tipo or ''}".lower():
            continue
        imp = float(item.importo or 0)
        tot_s += imp
        ci = inizio_ciclo(item.data)
        tl = "ricorrente" if item.tipo != TIPO_IMMEDIATO else "variabile"
        meta = f"{item.metodo or '—'} · {tl}" + (f" · acq. {data_breve(item.data_acquisto)}" if (is_carta_credito(item.metodo) and item.data_acquisto) else "")
        risultati.append({"sk": (item.data.toordinal(), item.id), "categoria": "spesa", "descrizione": item.descrizione or "Spesa", "importo_fmt": fmt_money(imp), "data_breve": data_breve(item.data), "anno": str(item.data.year), "ciclo_key": chiave_ciclo(ci), "ciclo_label": etichetta_ciclo(ci), "pagata": bool(item.pagata), "meta": meta})
    for item in qe.order_by(Entrata.data.desc(), Entrata.id.desc()).all():
        if testo and testo not in f"{item.descrizione or ''} {item.provenienza or ''}".lower():
            continue
        imp = float(item.importo or 0)
        tot_e += imp
        ci = inizio_ciclo(item.data)
        risultati.append({"sk": (item.data.toordinal(), item.id), "categoria": "entrata", "descrizione": item.descrizione or "Entrata", "importo_fmt": fmt_money(imp), "data_breve": data_breve(item.data), "anno": str(item.data.year), "ciclo_key": chiave_ciclo(ci), "ciclo_label": etichetta_ciclo(ci), "pagata": True, "meta": item.provenienza or "Entrata"})
    risultati.sort(key=lambda x: x["sk"], reverse=True)
    for r in risultati:
        r.pop("sk", None)
    return JSONResponse({"risultati": risultati[:200], "tot_spese_fmt": fmt_money(tot_s), "tot_entrate_fmt": fmt_money(tot_e)})


@app.post("/config")
def salva_config(
    pac: str = Form("10"),
    pac_modo: str = Form("perc"),
    cuscinetto: str = Form("0"),
    cuscinetto_modo: str = Form("perc"),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    def _num(v: str, default: float) -> float:
        try:
            return max(0.0, float(str(v).replace(",", ".").strip()))
        except (TypeError, ValueError):
            return default

    valori = {}
    if pac_modo == "eur":
        valori["pac_fisso"] = f"{_num(pac, 0.0):.2f}"
    else:
        valori["pac_fisso"] = "0.00"
        p_val = min(100.0, _num(pac, 10.0)) / 100.0
        valori["pac_percentuale"] = f"{p_val:.4f}"

    if cuscinetto_modo == "eur":
        valori["cuscinetto_fisso"] = f"{_num(cuscinetto, 0.0):.2f}"
    else:
        valori["cuscinetto_fisso"] = "0.00"
        c_val = min(100.0, _num(cuscinetto, 0.0)) / 100.0
        valori["cuscinetto_percentuale"] = f"{c_val:.4f}"

    for chiave, valore in valori.items():
        esistente = db.query(Config).filter(Config.chiave == chiave).first()
        if esistente:
            esistente.valore = valore
        else:
            db.add(Config(chiave=chiave, valore=valore))
    db.commit()
    return _back(ciclo, vista_metodo, oggi_italia())


# ---------------------------------------------------------------------------
# Azioni POST
# ---------------------------------------------------------------------------


@app.post("/add-spesa")
def add_spesa(
    descrizione: str = Form(""),
    importo: str = Form("0"),
    data: Optional[str] = Form(None),
    data_acquisto: Optional[str] = Form(None),
    metodo: str = Form("Contanti"),
    tipo: str = Form(TIPO_IMMEDIATO),
    ricorrenza: str = Form("nessuna"),
    num_rate: Optional[str] = Form(None),
    data_fine: Optional[str] = Form(None),
    pagata: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    giorno = parse_date(data, oggi_italia()) or oggi_italia()
    desc_pulita = (descrizione or "").strip() or "Spesa"
    imp_pulito = parse_importo(importo)
    met_pulito = metodo if metodo in METODI else "Contanti"
    tipo_pulito = "fissa" if ricorrenza in ("mensile", "annuale") else ((tipo or "").strip() or TIPO_IMMEDIATO)

    acq_parsed = parse_date(data_acquisto, None)
    if is_carta_credito(met_pulito):
        acq_effettiva = acq_parsed or giorno
        data_contabile = calcola_addebito_carta(met_pulito, acq_effettiva)
        pagata_effettiva = True
    elif met_pulito == "Da valutare":
        acq_effettiva = acq_parsed
        data_contabile = giorno
        pagata_effettiva = False
    else:
        acq_effettiva = acq_parsed
        data_contabile = giorno
        pagata_effettiva = pagata is not None

    spesa = Spesa(
        data=data_contabile,
        data_acquisto=acq_effettiva,
        descrizione=desc_pulita,
        importo=imp_pulito,
        metodo=met_pulito,
        tipo=tipo_pulito,
        pagata=pagata_effettiva,
    )
    db.add(spesa)
    if ricorrenza in ("mensile", "annuale"):
        n_rate = int(num_rate) if (num_rate and num_rate.strip().isdigit() and int(num_rate) > 0) else None
        d_fine = parse_date(data_fine, None)
        db.add(Ricorrenza(
            categoria="spesa",
            frequenza=ricorrenza,
            descrizione=desc_pulita,
            importo=imp_pulito,
            giorno_scadenza=giorno.day,
            mese_scadenza=giorno.month if ricorrenza == "annuale" else None,
            metodo=met_pulito,
            tipo_spesa="fissa",
            data_inizio=giorno,
            data_fine=d_fine,
            num_rate=n_rate,
            pagata=pagata_effettiva,
            attiva=True,
        ))
    db.commit()
    if ricorrenza in ("mensile", "annuale"):
        sincronizza_ricorrenze(db)
    return _back(ciclo, vista_metodo, giorno)


@app.post("/preleva-salvadanaio")
def preleva_salvadanaio(
    importo: str = Form("0"),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    oggi = oggi_italia()
    inizio = parse_chiave_ciclo(ciclo) or inizio_ciclo(oggi)
    fine = fine_ciclo(inizio)
    riporto_disp = calcola_riporto(db, inizio)
    gia_prelevati = (
        db.query(func.coalesce(func.sum(Entrata.importo), 0.0))
        .filter(
            Entrata.data >= inizio,
            Entrata.data <= fine,
            Entrata.provenienza == "Salvadanaio",
        )
        .scalar()
        or 0.0
    )
    max_prelevabile = max(0.0, round(riporto_disp - float(gia_prelevati), 2))
    imp = min(max_prelevabile, max(0.0, parse_importo(importo)))
    if imp > 0:
        data_mov = oggi if inizio <= oggi <= fine else inizio
        db.add(Entrata(
            descrizione="Prelievo da salvadanaio",
            importo=round(imp, 2),
            data=data_mov,
            provenienza="Salvadanaio",
        ))
        db.commit()
    return _back(ciclo, vista_metodo, inizio)


@app.post("/add-entrata")
def add_entrata(
    descrizione: str = Form(""),
    importo: str = Form("0"),
    data: Optional[str] = Form(None),
    provenienza: str = Form(""),
    ricorrenza: str = Form("nessuna"),
    num_rate: Optional[str] = Form(None),
    data_fine: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    giorno = parse_date(data, oggi_italia()) or oggi_italia()
    desc_pulita = (descrizione or "").strip() or "Entrata"
    imp_pulito = parse_importo(importo)
    prov_pulita = (provenienza or "").strip()

    entrata = Entrata(
        descrizione=desc_pulita,
        importo=imp_pulito,
        data=giorno,
        provenienza=prov_pulita,
    )
    db.add(entrata)
    if ricorrenza in ("mensile", "annuale"):
        n_rate = int(num_rate) if (num_rate and num_rate.strip().isdigit() and int(num_rate) > 0) else None
        d_fine = parse_date(data_fine, None)
        db.add(Ricorrenza(
            categoria="entrata",
            frequenza=ricorrenza,
            descrizione=desc_pulita,
            importo=imp_pulito,
            giorno_scadenza=giorno.day,
            mese_scadenza=giorno.month if ricorrenza == "annuale" else None,
            provenienza=prov_pulita,
            data_inizio=giorno,
            data_fine=d_fine,
            num_rate=n_rate,
            pagata=False,
            attiva=True,
        ))
    db.commit()
    if ricorrenza in ("mensile", "annuale"):
        sincronizza_ricorrenze(db)
    return _back(ciclo, vista_metodo, giorno)



@app.post("/add-ricorrenza")
def add_ricorrenza(
    categoria: str = Form("spesa"),
    frequenza: str = Form("mensile"),
    descrizione: str = Form(""),
    importo: str = Form("0"),
    data_inizio: Optional[str] = Form(None),
    data_fine: Optional[str] = Form(None),
    num_rate: Optional[str] = Form(None),
    metodo: str = Form("SDD"),
    provenienza: str = Form(""),
    pagata: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    giorno = parse_date(data_inizio, oggi_italia()) or oggi_italia()
    cat = "entrata" if categoria == "entrata" else "spesa"
    freq = "annuale" if frequenza == "annuale" else "mensile"
    desc_pulita = (descrizione or "").strip() or ("Entrata ricorrente" if cat == "entrata" else "Spesa ricorrente")
    imp_pulito = parse_importo(importo)
    met_pulito = metodo if metodo in METODI else "SDD"
    prov_pulita = (provenienza or "").strip()

    esistente = (
        db.query(Ricorrenza)
        .filter(
            Ricorrenza.attiva.is_(True),
            Ricorrenza.categoria == cat,
            Ricorrenza.frequenza == freq,
            func.lower(Ricorrenza.descrizione) == desc_pulita.lower(),
        )
        .first()
    )
    n_rate = int(num_rate) if (num_rate and num_rate.strip().isdigit() and int(num_rate) > 0) else None
    d_fine = parse_date(data_fine, None)
    if esistente:
        esistente.importo = imp_pulito
        esistente.giorno_scadenza = giorno.day
        esistente.mese_scadenza = giorno.month if freq == "annuale" else None
        esistente.metodo = met_pulito
        esistente.provenienza = prov_pulita
        esistente.data_inizio = giorno
        esistente.data_fine = d_fine
        esistente.num_rate = n_rate
        esistente.pagata = (cat == "spesa" and met_pulito != "Da valutare" and (bool(pagata) or is_carta_credito(met_pulito)))
    else:
        db.add(Ricorrenza(
            categoria=cat,
            frequenza=freq,
            descrizione=desc_pulita,
            importo=imp_pulito,
            giorno_scadenza=giorno.day,
            mese_scadenza=giorno.month if freq == "annuale" else None,
            metodo=met_pulito,
            provenienza=prov_pulita,
            tipo_spesa="fissa",
            data_inizio=giorno,
            data_fine=d_fine,
            num_rate=n_rate,
            pagata=(cat == "spesa" and met_pulito != "Da valutare" and (bool(pagata) or is_carta_credito(met_pulito))),
            attiva=True,
        ))
    db.commit()
    sincronizza_ricorrenze(db)
    return _back(ciclo, vista_metodo, giorno)


@app.post("/update-ricorrenza/{id}")
def update_ricorrenza(
    id: int,
    categoria: str = Form("spesa"),
    frequenza: str = Form("mensile"),
    descrizione: str = Form(""),
    importo: str = Form("0"),
    data_inizio: Optional[str] = Form(None),
    data_fine: Optional[str] = Form(None),
    num_rate: Optional[str] = Form(None),
    metodo: str = Form("SDD"),
    provenienza: str = Form(""),
    pagata: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    ric = db.get(Ricorrenza, id)
    if ric is None:
        raise HTTPException(status_code=404, detail="Ricorrenza non trovata")

    oggi = oggi_italia()
    vecchia_cat = ric.categoria
    vecchia_desc = (ric.descrizione or "").strip().lower()

    giorno = parse_date(data_inizio, ric.data_inizio or oggi) or oggi
    cat = "entrata" if categoria == "entrata" else "spesa"
    freq = "annuale" if frequenza == "annuale" else "mensile"
    desc_pulita = (descrizione or "").strip() or ("Entrata ricorrente" if cat == "entrata" else "Spesa ricorrente")
    imp_pulito = parse_importo(importo)
    met_pulito = metodo if metodo in METODI else "SDD"
    prov_pulita = (provenienza or "").strip()
    n_rate = int(num_rate) if (num_rate and num_rate.strip().isdigit() and int(num_rate) > 0) else None
    d_fine = parse_date(data_fine, None)

    if vecchia_cat == "entrata":
        db.query(Entrata).filter(
            func.lower(Entrata.descrizione) == vecchia_desc,
            Entrata.data >= oggi,
        ).delete(synchronize_session=False)
    else:
        db.query(Spesa).filter(
            func.lower(Spesa.descrizione) == vecchia_desc,
            Spesa.data >= inizio_ciclo(oggi),
            Spesa.pagata.is_(False),
        ).delete(synchronize_session=False)

    ric.categoria = cat
    ric.frequenza = freq
    ric.descrizione = desc_pulita
    ric.importo = imp_pulito
    ric.giorno_scadenza = giorno.day
    ric.mese_scadenza = giorno.month if freq == "annuale" else None
    ric.metodo = met_pulito
    ric.provenienza = prov_pulita
    ric.data_inizio = giorno
    ric.data_fine = d_fine
    ric.num_rate = n_rate
    ric.pagata = (cat == "spesa" and met_pulito != "Da valutare" and (bool(pagata) or is_carta_credito(met_pulito)))
    ric.attiva = True

    db.commit()
    sincronizza_ricorrenze(db)
    return _back(ciclo, vista_metodo, oggi)


@app.post("/delete-ricorrenza/{id}")
def delete_ricorrenza(
    id: int,
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    ric = db.get(Ricorrenza, id)
    if ric:
        ric.attiva = False
        oggi = oggi_italia()
        if ric.categoria == "entrata":
            db.query(Entrata).filter(
                func.lower(Entrata.descrizione) == (ric.descrizione or "").strip().lower(),
                Entrata.data > oggi,
            ).delete(synchronize_session=False)
        else:
            db.query(Spesa).filter(
                func.lower(Spesa.descrizione) == (ric.descrizione or "").strip().lower(),
                Spesa.data > oggi,
                Spesa.pagata.is_(False),
            ).delete(synchronize_session=False)
        db.commit()
    return _back(ciclo, vista_metodo, oggi_italia())


@app.post("/update-movimento/{tipo_orig}/{id}")
def update_movimento(
    tipo_orig: str,
    id: int,
    nuovo_tipo: Optional[str] = Form(None),
    descrizione: str = Form(""),
    importo: str = Form("0"),
    data: Optional[str] = Form(None),
    provenienza: str = Form(""),
    data_acquisto: Optional[str] = Form(None),
    metodo: str = Form("Contanti"),
    tipo: str = Form(TIPO_IMMEDIATO),
    pagata: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    tipo_normalizzato = (tipo_orig or "").lower()
    destinazione = (nuovo_tipo or tipo_normalizzato).lower()
    if destinazione not in ("spesa", "entrata"):
        destinazione = tipo_normalizzato

    if tipo_normalizzato == "spesa":
        spesa = db.get(Spesa, id)
        if spesa is None:
            raise HTTPException(status_code=404, detail="Spesa non trovata")
        giorno = parse_date(data, spesa.data) or spesa.data
        desc_pulita = (descrizione or "").strip() or "Spesa"
        imp_pulito = parse_importo(importo)
        if destinazione == "entrata":
            nuova_entrata = Entrata(
                data=giorno,
                descrizione=desc_pulita,
                importo=imp_pulito,
                provenienza=(provenienza or "").strip(),
            )
            db.add(nuova_entrata)
            db.delete(spesa)
        else:
            met_upd = metodo if metodo in METODI else "Contanti"
            acq_parsed = parse_date(data_acquisto, None)
            if is_carta_credito(met_upd):
                acq_effettiva = acq_parsed or giorno
                giorno = calcola_addebito_carta(met_upd, acq_effettiva)
                pagata_effettiva = True
            elif met_upd == "Da valutare":
                acq_effettiva = acq_parsed
                pagata_effettiva = False
            else:
                acq_effettiva = acq_parsed
                pagata_effettiva = pagata is not None
            spesa.data = giorno
            spesa.data_acquisto = acq_effettiva
            spesa.descrizione = desc_pulita
            spesa.importo = imp_pulito
            spesa.metodo = met_upd
            spesa.tipo = (tipo or "").strip() or TIPO_IMMEDIATO
            spesa.pagata = pagata_effettiva
        db.commit()
        return _back(ciclo, vista_metodo, giorno)

    if tipo_normalizzato == "entrata":
        entrata = db.get(Entrata, id)
        if entrata is None:
            raise HTTPException(status_code=404, detail="Entrata non trovata")
        giorno = parse_date(data, entrata.data) or entrata.data
        desc_pulita = (descrizione or "").strip() or "Entrata"
        imp_pulito = parse_importo(importo)
        if destinazione == "spesa":
            met_upd = metodo if metodo in METODI else "Contanti"
            acq_parsed = parse_date(data_acquisto, None)
            if is_carta_credito(met_upd):
                acq_effettiva = acq_parsed or giorno
                giorno = calcola_addebito_carta(met_upd, acq_effettiva)
                pagata_effettiva = True
            else:
                acq_effettiva = acq_parsed
                pagata_effettiva = pagata is not None
            nuova_spesa = Spesa(
                data=giorno,
                data_acquisto=acq_effettiva,
                descrizione=desc_pulita,
                importo=imp_pulito,
                metodo=met_upd,
                tipo=(tipo or "").strip() or TIPO_IMMEDIATO,
                pagata=pagata_effettiva,
            )
            db.add(nuova_spesa)
            db.delete(entrata)
        else:
            entrata.data = giorno
            entrata.descrizione = desc_pulita
            entrata.importo = imp_pulito
            entrata.provenienza = (provenienza or "").strip()
        db.commit()
        return _back(ciclo, vista_metodo, giorno)

    raise HTTPException(status_code=404, detail="Tipo movimento non valido")


@app.post("/toggle-pagata/{id}")
def toggle_pagata(
    id: int,
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    spesa = db.get(Spesa, id)
    if spesa is None:
        raise HTTPException(status_code=404, detail="Spesa non trovata")
    giorno = spesa.data
    spesa.pagata = not bool(spesa.pagata)
    db.commit()
    return _back(ciclo, vista_metodo, giorno)


@app.post("/delete-spesa/{id}")
def delete_spesa(
    id: int,
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    spesa = db.get(Spesa, id)
    if spesa is None:
        raise HTTPException(status_code=404, detail="Spesa non trovata")
    giorno = spesa.data
    db.delete(spesa)
    db.commit()
    return _back(ciclo, vista_metodo, giorno)


@app.post("/delete-entrata/{id}")
def delete_entrata(
    id: int,
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    entrata = db.get(Entrata, id)
    if entrata is None:
        raise HTTPException(status_code=404, detail="Entrata non trovata")
    giorno = entrata.data
    db.delete(entrata)
    db.commit()
    return _back(ciclo, vista_metodo, giorno)


@app.post("/delete-serie")
def delete_serie(
    id: Optional[int] = Form(None),
    descrizione: Optional[str] = Form(None),
    metodo: Optional[str] = Form(None),
    data: Optional[str] = Form(None),
    ciclo: Optional[str] = Form(None),
    vista_metodo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    if id is not None:
        target = db.get(Spesa, id)
        if target is None:
            raise HTTPException(status_code=404, detail="Spesa non trovata")
        ciclo_sel = parse_chiave_ciclo(ciclo) or inizio_ciclo(target.data)
        giorno = min(target.data, ciclo_sel)
        descrizione_serie = target.descrizione
        metodo_serie: Optional[str] = target.metodo
    else:
        if not descrizione:
            raise HTTPException(
                status_code=400,
                detail="Indicare l'id della spesa o la descrizione della serie",
            )
        giorno = parse_date(data, None) or inizio_ciclo(oggi_italia())
        descrizione_serie = descrizione
        metodo_serie = metodo

    filtri = [
        func.lower(Spesa.descrizione) == (descrizione_serie or "").strip().lower(),
        Spesa.data >= giorno,
    ]
    if metodo_serie is not None:
        filtri.append(Spesa.metodo == metodo_serie)
    (
        db.query(Spesa)
        .filter(*filtri)
        .delete(synchronize_session=False)
    )

    # Disattiva anche eventuale regola ricorrente collegata così non viene rigenerata nei cicli futuri
    ric_filtri = [
        Ricorrenza.attiva.is_(True),
        Ricorrenza.categoria == "spesa",
        func.lower(Ricorrenza.descrizione) == (descrizione_serie or "").strip().lower(),
    ]
    if metodo_serie is not None:
        ric_filtri.append(Ricorrenza.metodo == metodo_serie)
    for ric in db.query(Ricorrenza).filter(*ric_filtri).all():
        ric.attiva = False
    db.commit()
    return _back(ciclo, vista_metodo, giorno)


@app.api_route("/export-csv", methods=["GET", "POST"])
async def export_csv(
    request: Request,
    ciclo: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Response:
    if not ciclo and request.method == "POST":
        modulo = await request.form()
        valore = modulo.get("ciclo")
        if isinstance(valore, str):
            ciclo = valore
    inizio = parse_chiave_ciclo(ciclo) or inizio_ciclo(oggi_italia())
    fine = fine_ciclo(inizio)

    entrate = (
        db.query(Entrata)
        .filter(Entrata.data >= inizio, Entrata.data <= fine)
        .order_by(Entrata.data, Entrata.id)
        .all()
    )
    spese = (
        db.query(Spesa)
        .filter(Spesa.data >= inizio, Spesa.data <= fine)
        .order_by(Spesa.data, Spesa.id)
        .all()
    )

    registrazioni = []
    for entrata in entrate:
        registrazioni.append((
            entrata.data,
            0,
            entrata.id,
            [
                "Entrata",
                entrata.data.isoformat(),
                "",
                entrata.descrizione or "",
                f"{float(entrata.importo or 0):.2f}",
                entrata.provenienza or "",
                "",
                "",
            ],
        ))
    for spesa in spese:
        registrazioni.append((
            spesa.data,
            1,
            spesa.id,
            [
                "Spesa",
                spesa.data.isoformat(),
                spesa.data_acquisto.isoformat() if spesa.data_acquisto else "",
                spesa.descrizione or "",
                f"{float(spesa.importo or 0):.2f}",
                spesa.metodo or "",
                spesa.tipo or "",
                "sì" if spesa.pagata else "no",
            ],
        ))
    registrazioni.sort(key=lambda voce: (voce[0], voce[1], voce[2]))

    buffer = io.StringIO()
    scrittore = csv.writer(buffer, delimiter=",", lineterminator="\n")
    scrittore.writerow([
        "Tipo", "Data", "Data acquisto", "Descrizione", "Importo",
        "Metodo/Provenienza", "Tipo spesa", "Pagata",
    ])
    for _, _, _, riga in registrazioni:
        scrittore.writerow(riga)

    nome_file = f"movimenti_{chiave_ciclo(inizio)}.csv"
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nome_file}"'},
    )


@app.get("/fix-carte")
def fix_carte_supabase(db: Session = Depends(get_db)):
    spese_cc = db.query(Spesa).filter(Spesa.metodo.in_(list(CARTE_ATTIVE_MAP.keys()))).all()
    oggi = oggi_italia()
    conteggio = 0
    for s in spese_cc:
        da_acq = s.data_acquisto or s.data
        nuova_data = calcola_addebito_carta(s.metodo, da_acq)
        nuova_pagata = True
        if s.data != nuova_data or s.data_acquisto != da_acq or s.pagata != nuova_pagata:
            s.data_acquisto = da_acq
            s.data = nuova_data
            s.pagata = nuova_pagata
            conteggio += 1
    db.commit()
    return {"status": "ok", "aggiornate": conteggio}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
