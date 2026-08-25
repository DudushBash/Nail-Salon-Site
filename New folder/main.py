"""Vernis booking service: FastAPI, SQLite and a self-contained admin panel."""

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time as clock
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "bookings.db"

PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
ADMIN_LOGIN = os.getenv("ADMIN_LOGIN", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
SMS_WEBHOOK_URL = os.getenv("SMS_WEBHOOK_URL", "")
BOOKING_DAYS, SLOT_STEP_MINUTES = 60, 30
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
RATE_LIMITS: dict[str, deque] = defaultdict(deque)

DEFAULT_SERVICES = [
    ("classic", "Классический маникюр", 25, 40),
    ("gel", "Маникюр + гель-лак", 35, 70),
    ("combo", "Аппаратный маникюр", 30, 60),
    ("pedicure", "Педикюр классический", 40, 80),
]
# These values are deliberately editable in the salon settings screen.
DEFAULT_SETTINGS = {
    "salon_name": "Vernis", "address": "ул. Низами 45, Баку",
    "phone": "+994 XX XXX XX XX", "privacy_url": "/privacy.html",
    "language": "ru-RU", "currency": "AZN",
    "phone_regex": r"^\+994\d{9}$", "phone_placeholder": "+994 XX XXX XX XX",
    "monday": "10:00-20:00", "tuesday": "10:00-20:00",
    "wednesday": "10:00-20:00", "thursday": "10:00-20:00",
    "friday": "10:00-20:00", "saturday": "10:00-20:00", "sunday": "closed",
}

app = FastAPI(title="Vernis", version="2.1.0")


@contextmanager
def db():
    """Open a short SQLite transaction and always close it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}:{digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    salt_hex, digest = encoded.split(":", 1)
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1)
    return hmac.compare_digest(actual.hex(), digest)


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS services (
              id TEXT PRIMARY KEY, name TEXT NOT NULL, price INTEGER NOT NULL,
              duration INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS bookings (
              id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT, service TEXT,
              price INTEGER, duration INTEGER, day TEXT, time TEXT, client_name TEXT,
              client_phone TEXT, status TEXT DEFAULT 'new', cancel_token TEXT UNIQUE,
              consent_at TEXT, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS breaks (id INTEGER PRIMARY KEY AUTOINCREMENT, weekday INTEGER, start TEXT, end TEXT);
            CREATE TABLE IF NOT EXISTS closures (day TEXT PRIMARY KEY, label TEXT);
            CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT UNIQUE, password_hash TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, admin_id INTEGER, expires_at TEXT);
            CREATE TABLE IF NOT EXISTS notification_log (id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER, event TEXT, scheduled_for TEXT, sent_at TEXT, channel TEXT, error TEXT);
            CREATE INDEX IF NOT EXISTS idx_bookings_day ON bookings(day, time);
        """)
        # Migration for databases created by version 1.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(bookings)")}
        for name in ("cancel_token", "consent_at"):
            if name not in columns:
                conn.execute(f"ALTER TABLE bookings ADD COLUMN {name} TEXT")
        if not conn.execute("SELECT 1 FROM services LIMIT 1").fetchone():
            conn.executemany("INSERT INTO services(id,name,price,duration) VALUES(?,?,?,?)", DEFAULT_SERVICES)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings VALUES(?,?)", (key, value))
        if not conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            conn.execute("INSERT INTO admins(login,password_hash,created_at) VALUES(?,?,?)", (ADMIN_LOGIN, password_hash(ADMIN_PASSWORD), now()))


def get_settings() -> dict[str, str]:
    with db() as conn:
        return {row["key"]: row["value"] for row in conn.execute("SELECT * FROM settings")}


def clock_time(value: str):
    return datetime.strptime(value, "%H:%M").time()


def require_admin(token: Optional[str]):
    if not token:
        raise HTTPException(401, "Требуется вход")
    with db() as conn:
        session = conn.execute("SELECT s.*,a.login FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE token=? AND expires_at>?", (token, now())).fetchone()
    if not session:
        raise HTTPException(401, "Сессия истекла")
    return session


def available_slots(target: date, duration: int) -> list[str]:
    """Return slots excluding bookings, breaks, days off and closures."""
    if target < date.today() or target > date.today() + timedelta(days=BOOKING_DAYS):
        return []
    settings = get_settings()
    hours = settings.get(WEEKDAYS[target.weekday()], "closed")
    if hours == "closed":
        return []
    with db() as conn:
        if conn.execute("SELECT 1 FROM closures WHERE day=?", (target.isoformat(),)).fetchone():
            return []
        bookings = conn.execute("SELECT time,duration FROM bookings WHERE day=? AND status!='cancelled'", (target.isoformat(),)).fetchall()
        breaks = conn.execute("SELECT start,end FROM breaks WHERE weekday=?", (target.weekday(),)).fetchall()
    start_text, end_text = hours.split("-", 1)
    busy = [(datetime.combine(target, clock_time(row["time"])), row["duration"]) for row in bookings]
    for item in breaks:
        start = datetime.combine(target, clock_time(item["start"]))
        end = datetime.combine(target, clock_time(item["end"]))
        busy.append((start, int((end - start).seconds / 60)))
    cursor, closing = datetime.combine(target, clock_time(start_text)), datetime.combine(target, clock_time(end_text))
    result = []
    while cursor + timedelta(minutes=duration) <= closing:
        if all(not (cursor < begin + timedelta(minutes=length) and begin < cursor + timedelta(minutes=duration)) for begin, length in busy):
            result.append(cursor.strftime("%H:%M"))
        cursor += timedelta(minutes=SLOT_STEP_MINUTES)
    return result


def notification_text(booking: dict, event: str) -> tuple[str, str]:
    labels = {"new": "Новая запись", "confirmed": "Подтверждение", "cancelled": "Отмена", "reminder_day": "Напоминание за день", "reminder_hours": "Напоминание за несколько часов"}
    link = f"{PUBLIC_URL}/cancel.html?token={booking['cancel_token']}" if PUBLIC_URL else "PUBLIC_URL не настроен"
    return link, f"💅 {labels.get(event, event)} #{booking['id']}\n{booking['service']}: {booking['day']} {booking['time']}\n{booking['client_name']} {booking['client_phone']}\nОтмена: {link}"


def notify(booking: dict, event: str) -> None:
    """Notify the salon in Telegram and optionally hand client SMS to a webhook."""
    link, text = notification_text(booking, event)
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            ok = requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=8).ok
            with db() as conn: conn.execute("INSERT INTO notification_log(booking_id,event,sent_at,channel,error) VALUES(?,?,?,?,?)", (booking["id"], event, now() if ok else None, "telegram", None if ok else "telegram error"))
        except requests.RequestException as exc:
            with db() as conn: conn.execute("INSERT INTO notification_log(booking_id,event,channel,error) VALUES(?,?,?,?)", (booking["id"], event, "telegram", str(exc)[:160]))
    if SMS_WEBHOOK_URL:
        try: requests.post(SMS_WEBHOOK_URL, json={"phone": booking["client_phone"], "event": event, "text": text, "cancel_url": link}, timeout=8).raise_for_status()
        except requests.RequestException: pass


def send_due_reminders() -> None:
    """Run every 15 minutes; the log prevents duplicate reminders."""
    current = datetime.now()
    tomorrow = (current.date() + timedelta(days=1)).isoformat()
    low = (current + timedelta(hours=2, minutes=45)).strftime("%H:%M")
    high = (current + timedelta(hours=3, minutes=15)).strftime("%H:%M")
    with db() as conn:
        rows = conn.execute("SELECT * FROM bookings WHERE status IN ('new','confirmed') AND (day=? OR (day=? AND time BETWEEN ? AND ?))", (tomorrow, current.date().isoformat(), low, high)).fetchall()
    for row in rows:
        booking, event = dict(row), "reminder_day" if row["day"] == tomorrow else "reminder_hours"
        with db() as conn:
            sent = conn.execute("SELECT 1 FROM notification_log WHERE booking_id=? AND event=?", (booking["id"], event)).fetchone()
            if not sent: conn.execute("INSERT INTO notification_log(booking_id,event,scheduled_for,channel) VALUES(?,?,?,?)", (booking["id"], event, now(), "scheduler"))
        if not sent: notify(booking, event)


@app.on_event("startup")
async def reminders_worker():
    async def loop():
        while True:
            send_due_reminders()
            await asyncio.sleep(900)
    asyncio.create_task(loop())


class BookingIn(BaseModel):
    service_id: str = Field(max_length=50); day: date; time: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    client_name: str = Field(min_length=2, max_length=100); client_phone: str = Field(max_length=30); consent: bool
class LoginIn(BaseModel): login: str = Field(min_length=2); password: str = Field(min_length=8)
class ServiceIn(BaseModel): id: Optional[str] = None; name: str = Field(min_length=2, max_length=100); price: int = Field(ge=0, le=10000); duration: int = Field(ge=10, le=600); active: bool = True
class StatusIn(BaseModel): status: str = Field(pattern="^(new|confirmed|done|cancelled)$")
class ValuesIn(BaseModel): values: dict[str, str]
class BreakIn(BaseModel): weekday: int = Field(ge=0, le=6); start: str = Field(pattern=r"^\d\d:\d\d$"); end: str = Field(pattern=r"^\d\d:\d\d$")
class ClosureIn(BaseModel): day: date; label: str = Field(min_length=1, max_length=100)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith(("/api/bookings", "/api/auth")):
        requests_for_ip, current = RATE_LIMITS[request.client.host], clock.time()
        while requests_for_ip and requests_for_ip[0] < current - 60: requests_for_ip.popleft()
        if len(requests_for_ip) >= 20: return Response('{"detail":"Слишком много запросов"}', 429, media_type="application/json")
        requests_for_ip.append(current)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"; response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/health")
def health(): return {"ok": True}
@app.get("/api/settings")
def public_settings():
    data = get_settings(); return {key: data[key] for key in ("salon_name", "address", "phone", "privacy_url", "language", "currency", "phone_placeholder")}
@app.get("/api/services")
def services():
    with db() as conn: return [dict(row) for row in conn.execute("SELECT id,name,price,duration FROM services WHERE active=1 ORDER BY rowid")]
@app.get("/api/availability")
def availability(service_id: str, day: date):
    with db() as conn: service = conn.execute("SELECT duration FROM services WHERE id=? AND active=1", (service_id,)).fetchone()
    if not service: raise HTTPException(404, "Услуга не найдена")
    return {"day": day.isoformat(), "slots": available_slots(day, service["duration"])}
@app.post("/api/bookings")
def create_booking(payload: BookingIn):
    phone = re.sub(r"[^+\d]", "", payload.client_phone); config = get_settings()
    if not payload.consent: raise HTTPException(400, "Нужно согласие на обработку номера телефона")
    try: valid_phone = re.fullmatch(config["phone_regex"], phone)
    except re.error: raise HTTPException(500, "Некорректная настройка проверки телефона")
    if not valid_phone: raise HTTPException(400, f"Введите номер в формате {config['phone_placeholder']}")
    with db() as conn: service = conn.execute("SELECT * FROM services WHERE id=? AND active=1", (payload.service_id,)).fetchone()
    if not service: raise HTTPException(404, "Услуга не найдена")
    if payload.time not in available_slots(payload.day, service["duration"]): raise HTTPException(409, "Это время уже занято или недоступно")
    with db() as conn:
        cursor = conn.execute("INSERT INTO bookings(service_id,service,price,duration,day,time,client_name,client_phone,status,cancel_token,consent_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (service["id"], service["name"], service["price"], service["duration"], payload.day.isoformat(), payload.time, payload.client_name.strip(), phone, "new", secrets.token_urlsafe(32), now(), now()))
        booking = dict(conn.execute("SELECT * FROM bookings WHERE id=?", (cursor.lastrowid,)).fetchone())
    notify(booking, "new"); return {**booking, "cancel_url": f"{PUBLIC_URL}/cancel.html?token={booking['cancel_token']}" if PUBLIC_URL else None}
@app.get("/api/cancel/{token}")
def cancel_info(token: str):
    with db() as conn: booking = conn.execute("SELECT id,service,day,time,status FROM bookings WHERE cancel_token=?", (token,)).fetchone()
    if not booking: raise HTTPException(404, "Ссылка недействительна")
    return dict(booking)
@app.post("/api/cancel/{token}")
def cancel(token: str):
    with db() as conn:
        booking = conn.execute("SELECT * FROM bookings WHERE cancel_token=?", (token,)).fetchone()
        if not booking: raise HTTPException(404, "Ссылка недействительна")
        if booking["status"] == "done": raise HTTPException(409, "Выполненную запись отменить нельзя")
        conn.execute("UPDATE bookings SET status='cancelled' WHERE id=?", (booking["id"],))
    result = dict(booking); result["status"] = "cancelled"; notify(result, "cancelled"); return {"ok": True}
@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response):
    with db() as conn: admin = conn.execute("SELECT * FROM admins WHERE login=?", (payload.login,)).fetchone()
    if not admin or not password_matches(payload.password, admin["password_hash"]): raise HTTPException(401, "Неверный логин или пароль")
    token = secrets.token_urlsafe(32)
    with db() as conn: conn.execute("INSERT INTO sessions VALUES(?,?,?)", (token, admin["id"], (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()))
    response.set_cookie("vernis_session", token, httponly=True, samesite="lax", secure=PUBLIC_URL.startswith("https://"), max_age=604800)
    return {"ok": True, "login": admin["login"]}
@app.post("/api/auth/logout")
def logout(response: Response, vernis_session: Optional[str] = Cookie(None)):
    with db() as conn: conn.execute("DELETE FROM sessions WHERE token=?", (vernis_session,))
    response.delete_cookie("vernis_session"); return {"ok": True}
@app.get("/api/auth/me")
def me(vernis_session: Optional[str] = Cookie(None)): return {"login": require_admin(vernis_session)["login"]}
@app.get("/api/admin/dashboard")
def dashboard(start: date, end: date, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn:
        return {"bookings": [dict(x) for x in conn.execute("SELECT * FROM bookings WHERE day BETWEEN ? AND ? ORDER BY day,time", (start.isoformat(), end.isoformat()))], "services": [dict(x) for x in conn.execute("SELECT * FROM services ORDER BY rowid")], "breaks": [dict(x) for x in conn.execute("SELECT * FROM breaks")], "closures": [dict(x) for x in conn.execute("SELECT * FROM closures WHERE day BETWEEN ? AND ?", (start.isoformat(), end.isoformat()))], "settings": get_settings()}
@app.patch("/api/admin/bookings/{booking_id}")
def update_status(booking_id: int, payload: StatusIn, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn: conn.execute("UPDATE bookings SET status=? WHERE id=?", (payload.status, booking_id)); booking = conn.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
    if not booking: raise HTTPException(404, "Запись не найдена")
    if payload.status == "confirmed": notify(dict(booking), "confirmed")
    return {"ok": True}
@app.post("/api/admin/services")
def save_service(payload: ServiceIn, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session); service_id = payload.id or secrets.token_hex(6)
    with db() as conn: conn.execute("INSERT INTO services VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,price=excluded.price,duration=excluded.duration,active=excluded.active", (service_id, payload.name, payload.price, payload.duration, int(payload.active)))
    return {"id": service_id}
@app.put("/api/admin/settings")
def save_settings(payload: ValuesIn, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn:
        for key, value in payload.values.items():
            if key in DEFAULT_SETTINGS and len(value) <= 200: conn.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value.strip()))
    return get_settings()
@app.post("/api/admin/breaks")
def add_break(payload: BreakIn, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    if clock_time(payload.end) <= clock_time(payload.start): raise HTTPException(400, "Некорректное время")
    with db() as conn: cursor = conn.execute("INSERT INTO breaks(weekday,start,end) VALUES(?,?,?)", (payload.weekday, payload.start, payload.end))
    return {"id": cursor.lastrowid}
@app.delete("/api/admin/breaks/{break_id}")
def delete_break(break_id: int, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn: conn.execute("DELETE FROM breaks WHERE id=?", (break_id,))
    return {"ok": True}
@app.post("/api/admin/closures")
def add_closure(payload: ClosureIn, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn: conn.execute("INSERT INTO closures VALUES(?,?) ON CONFLICT(day) DO UPDATE SET label=excluded.label", (payload.day.isoformat(), payload.label))
    return {"ok": True}
@app.delete("/api/admin/closures/{closure_day}")
def delete_closure(closure_day: date, vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    with db() as conn: conn.execute("DELETE FROM closures WHERE day=?", (closure_day.isoformat(),))
    return {"ok": True}
@app.get("/api/admin/backup")
def backup(vernis_session: Optional[str] = Cookie(None)):
    require_admin(vernis_session)
    from fastapi.responses import FileResponse
    return FileResponse(DB_PATH, filename=f"vernis-backup-{date.today().isoformat()}.db")


init_db()
app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
