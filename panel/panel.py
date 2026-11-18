#!/usr/bin/env python3
"""Panel web de CrowdSec — dashboard completo, stdlib sin dependencias (v2.2).

Vistas equivalentes a crowdsec-web-ui, implementación propia:
dashboard, alertas (búsqueda + borrado), decisiones (ban/unban manual),
estadísticas a largo plazo (SQLite local), allowlists (solo lectura),
métricas, notificaciones (campana local + webhook opcional de Discord,
ntfy o Gotify) y ajustes con auditoría. SIN LOGIN por defecto: si no hay
PANEL_UI_PASSWORD el panel es de solo lectura; con contraseña, login → token
de sesión por cabecera y escrituras habilitadas.

Seguridad:
  - Rutas cerradas (lista blanca). Contra la LAPI solo se emiten: login del
    watcher, GET /v1/{alerts,decisions}, POST /v1/decisions (ban manual),
    DELETE /v1/decisions (unban) y DELETE /v1/alerts (borrar alertas),
    SIEMPRE con cuerpo/query construidos aquí (nunca passthrough del cliente).
  - Mutaciones: sesión válida + Origin propio + Content-Type JSON + validación
    estricta (ipaddress, duración máx 30 días, motivo saneado) + rate-limit
    + auditoría en SQLite. CSRF: sin cookies, token por cabecera custom y
    JSON obligatorio → un formulario externo no puede forjarlas.
  - Histórico, notificaciones y auditoría en SQLite local (/data): nada sale
    salvo el webhook que TÚ configures (solo el texto del aviso).
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socketserver
import sqlite3
import threading
import time
import http.server
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

LAPI = os.environ.get("PANEL_LAPI_URL", "http://crowdsec:8080").rstrip("/")
USER = os.environ.get("PANEL_USER", "panel")
PASS = os.environ.get("PANEL_PASS", "")
PORT = int(os.environ.get("PANEL_PORT", "8096"))
STATIC = os.environ.get("PANEL_STATIC", "/srv/index.html")
DATA_DIR = os.environ.get("PANEL_DATA_DIR", "/data")
WHITELIST_FILE = os.environ.get("PANEL_WHITELIST_FILE", "")
METRICS_URL = os.environ.get("PANEL_METRICS_URL", "http://crowdsec:6060").rstrip("/")
UI_PASSWORD = os.environ.get("PANEL_UI_PASSWORD", "")
NOTIFY_URL = os.environ.get("NOTIFY_URL", "").strip()
POLL = max(1, int(os.environ.get("PANEL_POLL_SECONDS", "30")))
DB_PATH = os.path.join(DATA_DIR, "panel.db")
MAX_BAN_SECS = 30 * 24 * 3600
VERSION = "2.2"

STATE_LOCK = threading.Lock()
state = {"token": None, "ts": 0.0, "lapi_up": None, "last_poll": 0.0,
         "prev_values": None, "started": time.time(), "metrics_ok": None}

sessions = {}          # token → expiry (máx 5 sesiones, 12 h)
login_fails = []       # timestamps de logins fallidos (ventana 5 min)
rate = {}              # ruta → [timestamps]
counters = {"requests": 0, "bans": 0, "unbans": 0, "deletes": 0, "logins_ok": 0}


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ago(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts(
          id INTEGER PRIMARY KEY, created_at TEXT, scenario TEXT, message TEXT,
          source_ip TEXT, country TEXT, as_name TEXT, machine TEXT,
          events_count INTEGER, has_ban INTEGER, raw TEXT, ingested TEXT);
        CREATE TABLE IF NOT EXISTS decisions_hist(
          value TEXT, reason TEXT, until_at TEXT, created_at TEXT,
          first_seen TEXT, last_active TEXT, expired_at TEXT, origin TEXT,
          PRIMARY KEY(value, created_at));
        CREATE TABLE IF NOT EXISTS notifs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, ref TEXT,
          title TEXT, body TEXT, sent INTEGER, UNIQUE(kind, ref));
        CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, detail TEXT, ok INTEGER);
        """)


def audit(action, detail="", ok=1):
    try:
        with db() as c:
            c.execute("INSERT INTO audit(ts, action, detail, ok) VALUES(?,?,?,?)",
                      (utcnow(), action, json.dumps(detail, ensure_ascii=False)[:2000], ok))
    except Exception:
        pass


# ── LAPI ──────────────────────────────────────────────────────────────────────
def lapi_login():
    req = urllib.request.Request(
        LAPI + "/v1/watchers/login",
        data=json.dumps({"username": USER, "password": PASS}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        tok = json.load(resp).get("token")
    if not tok:
        raise RuntimeError("login LAPI sin token")
    state["token"], state["ts"] = tok, time.time()


def lapi_request(method, path, obj=None, timeout=15):
    """Única puerta hacia la LAPI. `path` SIEMPRE lo construye el panel."""
    if not state["token"] or time.time() - state["ts"] > 45 * 60:
        with STATE_LOCK:
            if not state["token"] or time.time() - state["ts"] > 45 * 60:
                lapi_login()
    data = json.dumps(obj).encode() if obj is not None else None
    headers = {"Authorization": "Bearer " + state["token"]}
    if data:
        headers["Content-Type"] = "application/json"
    for intento in (1, 2):
        req = urllib.request.Request(LAPI + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and intento == 1:
                with STATE_LOCK:
                    lapi_login()
                continue
            return e.code, e.read()[:2000]
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if intento == 1:
                continue
            return 502, json.dumps({"error": "LAPI inalcanzable: %s" % e}).encode()
    return 502, json.dumps({"error": "LAPI sin respuesta"}).encode()


# ── Ingesta local (SQLite) ────────────────────────────────────────────────────
def ingest_alerts(alerts):
    now = utcnow()
    with db() as c:
        for a in alerts:
            src = a.get("source") or {}
            try:
                c.execute(
                    "INSERT OR IGNORE INTO alerts(id, created_at, scenario, message, source_ip,"
                    " country, as_name, machine, events_count, has_ban, raw, ingested)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.get("id"), a.get("created_at"), a.get("scenario"), a.get("message") or "",
                     src.get("value") or "", src.get("country") or "", src.get("as_name") or "",
                     a.get("machine") or "", a.get("events_count") or 0,
                     1 if a.get("decisions") else 0, json.dumps(a, ensure_ascii=False)[:8000], now))
            except Exception:
                pass


def ingest_decisions(active):
    now = utcnow()
    seen = set()
    with db() as c:
        for d in active:
            key = (d.get("value") or "", d.get("created_at") or "")
            if not key[0]:
                continue
            seen.add(key[0])
            c.execute("INSERT OR IGNORE INTO decisions_hist(value, reason, until_at, created_at,"
                      " first_seen, last_active, expired_at, origin) VALUES(?,?,?,?,?,?,NULL,?)",
                      (key[0], d.get("reason") or d.get("scenario") or "", d.get("until_at") or "",
                       key[1], now, now, "lapi"))
            c.execute("UPDATE decisions_hist SET last_active=? WHERE value=? AND created_at=?"
                      " AND expired_at IS NULL", (now, key[0], key[1]))
        c.execute("UPDATE decisions_hist SET expired_at=? WHERE expired_at IS NULL AND value NOT IN"
                  " (%s)" % ",".join("?" * len(seen) or "''"), (now, *seen))
    # detección de baneos NUEVOS (para notificaciones)
    prev = state["prev_values"]
    if prev is not None and notify_cfg().get("new_ban"):
        for d in active:
            v = d.get("value") or ""
            if v and v not in prev:
                add_notif("ban", "%s@%s" % (v, d.get("until_at") or ""), "Nuevo baneo: " + v,
                          "Motivo: %s · dura hasta %s" % (d.get("reason") or "?", d.get("until_at") or "?"))
    state["prev_values"] = {d.get("value") for d in active if d.get("value")}


def get_setting(key, default):
    try:
        with db() as c:
            row = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
            return json.loads(row["v"]) if row else default
    except Exception:
        return default


def save_setting(key, value):
    with db() as c:
        c.execute("INSERT INTO settings(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                  (key, json.dumps(value)))


def notify_cfg():
    cfg = get_setting("notify", {})
    return {"new_ban": int(bool(cfg.get("new_ban", 1))),
            "spike": max(1, int(cfg.get("spike") or 50)),
            "url": (cfg.get("url") or NOTIFY_URL).strip()}


def add_notif(kind, ref, title, body):
    """Registra una notificación y la manda al webhook si hay destino.
    Dedupe ANTES de enviar: si (kind, ref) ya existe, no se re-envía al
    webhook en cada sondeo (evita spam de Discord y repeticiones)."""
    try:
        with db() as c:
            if c.execute("SELECT 1 FROM notifs WHERE kind=? AND ref=?",
                         (kind, ref)).fetchone():
                return
    except Exception:
        pass
    url = notify_cfg().get("url", "")
    sent = 0
    if url and url.startswith("http"):
        try:
            if is_discord(url):
                payload = {"username": "CrowdSec",
                           "content": ("**%s**\n%s" % (title, body))[:1900],
                           "allowed_mentions": {"parse": []}}
            else:  # ntfy / Gotify / genérico JSON
                payload = {"title": title, "body": body}
            req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=8)
            sent = 1
        except Exception:
            sent = 0
    try:
        with db() as c:
            c.execute("INSERT OR IGNORE INTO notifs(ts, kind, ref, title, body, sent)"
                      " VALUES(?,?,?,?,?,?)", (utcnow(), kind, ref, title, body, sent))
    except Exception:
        pass


def is_discord(url):
    host = urllib.parse.urlsplit(url).netloc.lower()
    return host.endswith("discord.com") or host.endswith("discordapp.com")


def eval_spike():
    cfg = notify_cfg()
    with db() as c:
        n = c.execute("SELECT COUNT(*) n FROM alerts WHERE created_at >= ?",
                      (iso_ago(3600),)).fetchone()["n"]
    if n >= cfg["spike"]:
        bucket = utcnow()[:13]  # una notificación por hora como máximo
        add_notif("spike", bucket, "Pico de alertas", "%d alertas en la última hora (umbral %d)" % (n, cfg["spike"]))


def poll_once():
    try:
        code, body = lapi_request("GET", "/v1/alerts?limit=100")
        if code == 200:
            data = json.loads(body)
            if isinstance(data, list):
                ingest_alerts(data)
            state["lapi_up"] = True
        else:
            state["lapi_up"] = False
        code, body = lapi_request("GET", "/v1/decisions")
        if code == 200:
            data = json.loads(body)
            ingest_decisions(data.get("decisions") or [] if isinstance(data, dict) else [])
    except Exception:
        state["lapi_up"] = False
    eval_spike()
    state["last_poll"] = time.time()


def poll_loop():
    while True:
        poll_once()
        time.sleep(POLL)


# ── Allowlists (parser minimalista YAML, SOLO LECTURA) ────────────────────────
def parse_whitelist():
    out = {"configured": False, "file": WHITELIST_FILE, "name": "", "description": "", "entries": []}
    if not WHITELIST_FILE or not os.path.exists(WHITELIST_FILE):
        return out
    out["configured"] = True
    section = sub = None
    for line in open(WHITELIST_FILE, encoding="utf-8", errors="replace"):
        line = line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(name|description):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
            continue
        if re.match(r"^whitelist:\s*$", line):
            section = "whitelist"
            continue
        if section == "whitelist":
            m = re.match(r"^\s+(ip|regex|cidr|ranges):\s*$", line)
            if m:
                sub = m.group(1)
                continue
            m = re.match(r'^\s+-\s*"?([^"#]+?)"?\s*$', line)
            if m and sub:
                out["entries"].append({"kind": "ip" if sub in ("ip", "cidr", "ranges") else "regex",
                                       "value": m.group(1).strip()})
    return out


def ip_allowlisted(ip):
    wl = parse_whitelist()
    for e in wl["entries"]:
        try:
            if e["kind"] == "ip" and ipaddress.ip_address(ip) in ipaddress.ip_network(e["value"], strict=False):
                return e["value"]
            if e["kind"] == "regex" and re.fullmatch(e["value"], ip):
                return e["value"]
        except Exception:
            continue
    return None


# ── Validación de entrada ─────────────────────────────────────────────────────
def valid_ip(s):
    try:
        ipaddress.ip_address(str(s))
        return str(s)
    except ValueError:
        return None


def duration_secs(s):
    m = re.match(r"^(\d{1,5})([smhd])$", str(s or "").strip())
    if not m:
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    secs = int(m.group(1)) * mult
    return secs if 0 < secs <= MAX_BAN_SECS else None


def clean_text(s, limit=120):
    return re.sub(r"[^\w \-.,:/()áéíóúÁÉÍÓÚñÑ¿?]", "", str(s or ""))[:limit]


def valid_notify_url(s):
    s = str(s or "").strip()
    return s[:200] if re.match(r"^https?://[\w.\-:]{1,150}(/\S*)?$", s) else ""


def rate_ok(route, limit=10, window=60):
    now = time.time()
    with STATE_LOCK:
        arr = [t for t in rate.get(route, []) if now - t < window]
        if len(arr) >= limit:
            rate[route] = arr
            return False
        arr.append(now)
        rate[route] = arr
        return True


def session_ok(headers):
    """Lecturas: abiertas si no hay contraseña; con contraseña, token obligatorio.
    Escrituras: el token es SIEMPRE obligatorio (capa 1)."""
    if not UI_PASSWORD:
        return None  # modo público de lectura
    tok = headers.get("X-Panel-Token", "")
    exp = sessions.get(tok)
    if not tok or not exp or exp < time.time():
        return "invalid"
    return True


def mutation_guard(self):
    """Capas 1-4 de las operaciones de escritura. Devuelve None si pasa, o (msg, code)."""
    if UI_PASSWORD:
        if session_ok(self.headers) is not True:
            return "sin sesión válida (haz login)", 401
    else:
        return "escrituras bloqueadas: define PANEL_UI_PASSWORD en .env", 403
    origin = self.headers.get("Origin")
    if origin:
        try:
            if urllib.parse.urlsplit(origin).netloc != self.headers.get("Host", ""):
                return "origin no permitido", 403
        except Exception:
            return "origin inválido", 403
    if not self.headers.get("Content-Type", "").startswith("application/json"):
        return "content-type debe ser application/json", 400
    return None


# ── Estadísticas desde SQLite ─────────────────────────────────────────────────
def stats_payload(hours):
    with db() as c:
        cond = "WHERE created_at >= ?" if hours else ""
        args = (iso_ago(hours * 3600),) if hours else ()
        total = c.execute("SELECT COUNT(*) n FROM alerts " + cond, args).fetchone()["n"]
        uniq = c.execute("SELECT COUNT(DISTINCT source_ip) n FROM alerts " + cond, args).fetchone()["n"]
        prev_total = 0
        if hours:
            prev_total = c.execute("SELECT COUNT(*) n FROM alerts WHERE created_at >= ? AND created_at < ?",
                                   (iso_ago(2 * hours * 3600), iso_ago(hours * 3600))).fetchone()["n"]
        days = [dict(r) for r in c.execute(
            "SELECT substr(created_at,1,10) d, COUNT(*) n FROM alerts " + cond +
            " GROUP BY d ORDER BY d", args)]
        top_ips = [dict(r) for r in c.execute(
            "SELECT source_ip ip, COUNT(*) n, COUNT(DISTINCT substr(created_at,1,10)) dias,"
            " MAX(created_at) last FROM alerts " + cond +
            " GROUP BY source_ip ORDER BY n DESC LIMIT 20", args)]
        cond2 = (cond + " AND ") if hours else "WHERE "
        countries = [dict(r) for r in c.execute(
            "SELECT country, COUNT(*) n FROM alerts " + cond2 + "country != ''"
            " GROUP BY country ORDER BY n DESC LIMIT 10", args)]
        scenarios = [dict(r) for r in c.execute(
            "SELECT scenario, COUNT(*) n, SUM(has_ban) baneadas FROM alerts " + cond2 +
            "scenario != '' GROUP BY scenario ORDER BY n DESC LIMIT 10", args)]
        ases = [dict(r) for r in c.execute(
            "SELECT as_name, COUNT(*) n FROM alerts " + cond2 + "as_name != ''"
            " GROUP BY as_name ORDER BY n DESC LIMIT 10", args)]
        rec = [dict(r) for r in c.execute(
            "SELECT source_ip ip, COUNT(*) n, COUNT(DISTINCT substr(created_at,1,10)) dias"
            " FROM alerts " + cond + " GROUP BY source_ip"
            " HAVING dias >= 2 ORDER BY dias DESC, n DESC LIMIT 15", args)]
        bans = c.execute("SELECT COUNT(DISTINCT value) n FROM decisions_hist WHERE first_seen >= ?"
                         if hours else "SELECT COUNT(DISTINCT value) n FROM decisions_hist",
                         args).fetchone()["n"]
        covered = c.execute("SELECT COALESCE(SUM(has_ban),0) n FROM alerts " + cond,
                            args).fetchone()["n"]
        dec_days = [dict(r) for r in c.execute(
            "SELECT substr(first_seen,1,10) d, COUNT(DISTINCT value) n FROM decisions_hist" +
            ((" WHERE first_seen >= ?") if hours else "") + " GROUP BY d ORDER BY d", args)]

    # /24 dominante y hallazgos automáticos (agregado en Python)
    per24 = {}
    with db() as c:
        rows = c.execute("SELECT source_ip ip, COUNT(*) n FROM alerts " + cond +
                         " GROUP BY source_ip" if hours else
                         "SELECT source_ip ip, COUNT(*) n FROM alerts GROUP BY source_ip", args).fetchall()
    for r in rows:
        ip = r["ip"] or ""
        if ":" not in ip and "." in ip:  # solo IPv4 para el análisis /24
            per24[ip.rsplit(".", 1)[0] + ".0/24"] = per24.get(ip.rsplit(".", 1)[0] + ".0/24", 0) + r["n"]
    top24 = sorted(per24.items(), key=lambda kv: -kv[1])[:5]

    findings = []
    if days:
        daily_avg = total / max(1, len(days))
        with db() as c:
            last_hour = c.execute("SELECT COUNT(*) n FROM alerts WHERE created_at >= ?",
                                  (iso_ago(3600),)).fetchone()["n"]
        if last_hour and last_hour >= max(5, 2 * daily_avg):
            findings.append("Pico detectado: %d alertas en la última hora (media diaria %.1f)" % (last_hour, daily_avg))
    if top24 and total and top24[0][1] >= 10 and top24[0][1] / total >= 0.5:
        findings.append("La red %s concentra %d de %d alertas (%.0f%%)" %
                        (top24[0][0], top24[0][1], total, 100 * top24[0][1] / total))
    never_banned = [s for s in scenarios if s["scenario"] and not s["baneadas"]]
    if never_banned:
        findings.append("Escenario sin ninguna remediación: %s (%d alertas)" %
                        (never_banned[0]["scenario"], never_banned[0]["n"]))
    if rec:
        findings.append("%d IPs atacantes han vuelto en 2+ días distintos — considera duraciones largas o allowlist inversa" % len(rec))
    with db() as c:
        machs = [dict(r) for r in c.execute(
            "SELECT machine, MAX(created_at) last FROM alerts WHERE machine != '' GROUP BY machine")]
    for m in machs:
        if m["last"] < iso_ago(3 * 24 * 3600):
            findings.append("La máquina '%s' no genera alertas desde %s (¿está viva?)" % (m["machine"], m["last"][:16]))

    return {"hours": hours, "total": total, "uniq": uniq, "prev_total": prev_total,
            "days": days, "decs_days": dec_days, "covered": covered,
            "top_ips": top_ips, "recurrent": rec, "countries": countries,
            "scenarios": scenarios, "as": ases, "top24": top24, "bans": bans,
            "findings": findings[:6]}


# ── Búsqueda de alertas ───────────────────────────────────────────────────────
def search_alerts(q, page, size=50):
    where, params = [], []
    for tok in (q or "").split():
        m = re.match(r'^(country|scenario|ip|as|machine|date):"?([^"]+?)"?$', tok, re.I)
        if m:
            col, val = m.group(1).lower(), m.group(2).strip('"')
            colmap = {"country": "country", "scenario": "scenario", "as": "as_name",
                      "machine": "machine", "ip": "source_ip"}
            if col == "date":
                where.append("substr(created_at,1,10) >= ?")
                params.append(val)
            else:
                where.append(colmap[col] + " LIKE ?")
                params.append(val + "%")
        else:
            where.append("(message LIKE ? OR source_ip LIKE ? OR scenario LIKE ? OR as_name LIKE ?)")
            params += ["%" + tok + "%"] * 4
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    off = max(0, (page - 1)) * size
    with db() as c:
        total = c.execute("SELECT COUNT(*) n FROM alerts " + clause, params).fetchone()["n"]
        rows = [dict(r) for r in c.execute(
            "SELECT id, created_at, scenario, message, source_ip, country, as_name, machine,"
            " events_count, has_ban FROM alerts " + clause +
            " ORDER BY created_at DESC LIMIT ? OFFSET ?", (*params, size, off))]
    return {"total": total, "page": page, "size": size, "alerts": rows}


# ── Métricas propias (formato Prometheus) ─────────────────────────────────────
def panel_metrics():
    with STATE_LOCK:
        vals = dict(counters)
    vals["lapi_up"] = 1 if state["lapi_up"] else 0
    vals["uptime"] = int(time.time() - state["started"])
    lines = ["# HELP panel_metric Métricas internas del panel",
             "# TYPE panel_metric gauge"]
    names = {"requests": "panel_http_requests_total", "bans": "panel_bans_total",
             "unbans": "panel_unbans_total", "deletes": "panel_alert_deletes_total",
             "logins_ok": "panel_logins_total", "lapi_up": "panel_lapi_up",
             "uptime": "panel_uptime_seconds"}
    for k, name in names.items():
        lines.append("%s %s" % (name, vals[k]))
    return ("\n".join(lines) + "\n").encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _respond(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._respond(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def _read_json(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        if len(raw) > 100_000:
            raise ValueError("cuerpo demasiado grande")
        obj = json.loads(raw.decode("utf-8", "replace"))
        return obj if isinstance(obj, dict) else {}

    def do_GET(self):
        with STATE_LOCK:
            counters["requests"] += 1
        try:
            path, _, qs = self.path.partition("?")
            if path in ("/", "/index.html"):
                with open(STATIC, "rb") as fh:
                    self._respond(200, fh.read(), "text/html; charset=utf-8")
                return
            if path == "/api/session":
                self._json(200, {"auth_required": bool(UI_PASSWORD),
                                 "ok": session_ok(self.headers) is True})
                return
            if path == "/metrics":
                self._respond(200, panel_metrics(), "text/plain; charset=utf-8")
                return
            # ── lecturas protegidas (con contraseña) ──
            if UI_PASSWORD and session_ok(self.headers) is not True:
                self._json(401, {"error": "sesión no válida"})
                return
            if path.startswith(("/v1/alerts", "/v1/decisions")):
                code, body = lapi_request("GET", path + (("?" + qs) if qs else ""))
                self._respond(code if code != 502 else 502, body, "application/json")
                return
            if path == "/api/stats":
                hours = {"1": 24, "7": 24 * 7, "30": 24 * 30, "all": 0}.get(
                    urllib.parse.parse_qs(qs).get("range", ["7"])[0], 24 * 7)
                self._json(200, stats_payload(hours))
                return
            if path == "/api/alerts-search":
                p = urllib.parse.parse_qs(qs)
                self._json(200, search_alerts((p.get("q") or [""])[0][:500],
                                              int(p.get("page", ["1"])[0]) if p.get("page", ["1"])[0].isdigit() else 1))
                return
            if path == "/api/alert-detail":
                p = urllib.parse.parse_qs(qs)
                aid = (p.get("id") or [""])[0]
                if not aid.isdigit():
                    self._json(400, {"error": "id inválido"})
                    return
                code, body = lapi_request("GET", "/v1/alerts/" + aid)
                self._respond(code if code != 502 else 502, body, "application/json")
                return
            if path == "/api/decisions-history":
                with db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT value, reason, until_at, created_at, first_seen, last_active,"
                        " expired_at, origin FROM decisions_hist ORDER BY first_seen DESC LIMIT 300")]
                self._json(200, {"decisions": rows})
                return
            if path == "/api/allowlists":
                self._json(200, parse_whitelist())
                return
            if path == "/api/notifications":
                with db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT id, ts, kind, title, body, sent FROM notifs ORDER BY id DESC LIMIT 100")]
                self._json(200, {"notifications": rows, "url_configured": bool(notify_cfg()["url"])})
                return
            if path == "/api/audit":
                with db() as c:
                    rows = [dict(r) for r in c.execute(
                        "SELECT ts, action, detail, ok FROM audit ORDER BY id DESC LIMIT 100")]
                self._json(200, {"audit": rows})
                return
            if path == "/api/panel-info":
                with db() as c:
                    n_alerts = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
                    n_active = c.execute("SELECT COUNT(*) n FROM decisions_hist WHERE expired_at IS NULL").fetchone()["n"]
                with STATE_LOCK:
                    cnt = dict(counters)
                self._json(200, {"version": VERSION, "uptime_s": int(time.time() - state["started"]),
                                 "lapi_up": state["lapi_up"], "last_poll": state["last_poll"],
                                 "alerts_in_db": n_alerts, "decisions_active_db": n_active,
                                 "counters": cnt, "started": state["started"],
                                 "password_mode": bool(UI_PASSWORD), "poll_seconds": POLL,
                                 "notify_cfg": notify_cfg(), "metrics_ok": state["metrics_ok"]})
                return
            if path == "/api/crowdsec-metrics":
                try:
                    with urllib.request.urlopen(METRICS_URL + "/metrics", timeout=4) as r:
                        raw = r.read(400_000)
                    state["metrics_ok"] = True
                    keep = [ln for ln in raw.decode("utf-8", "replace").splitlines()
                            if ln.startswith("crowdsec_") or ln.startswith("#")]
                    self._respond(200, ("\n".join(keep[:800]) + "\n").encode(), "text/plain; charset=utf-8")
                except Exception as e:
                    state["metrics_ok"] = False
                    self._json(503, {"error": "métricas de CrowdSec no disponibles en %s (%s). "
                                             "Actívalas en config.yaml (ver README §6)." % (METRICS_URL, e)})
                return
            self._json(404, {"error": "ruta no permitida"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            try:
                self._json(500, {"error": "error interno del panel"})
            except Exception:
                pass

    def do_POST(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            guard = mutation_guard(self) if path != "/login" else None
            if guard:
                self._json(guard[1], {"error": guard[0]})
                return
            if not rate_ok(path):
                self._json(429, {"error": "demasiadas peticiones, espera un minuto"})
                return
            body = self._read_json()

            if path == "/login":
                if not UI_PASSWORD:
                    self._json(400, {"error": "sin PANEL_UI_PASSWORD configurada"})
                    return
                now = time.time()
                if len([t for t in login_fails if now - t < 300]) >= 8:
                    self._json(429, {"error": "demasiados intentos fallidos: espera 5 minutos"})
                    return
                if hmac.compare_digest(str(body.get("password", "")), UI_PASSWORD):
                    tok = secrets.token_hex(32)
                    now2 = time.time()
                    for t, exp in list(sessions.items()):
                        if exp < now2:
                            sessions.pop(t, None)
                    while len(sessions) >= 5:  # máx 5 sesiones: se descarta la más antigua
                        sessions.pop(min(sessions, key=lambda k: sessions[k]))
                    sessions[tok] = now2 + 12 * 3600
                    with STATE_LOCK:
                        counters["logins_ok"] += 1
                    self._json(200, {"token": tok, "expires_in": 12 * 3600})
                else:
                    login_fails.append(now)
                    audit("login-fallido", {"origin": self.headers.get("Origin") or ""}, ok=0)
                    self._json(403, {"error": "contraseña incorrecta"})
                return

            if UI_PASSWORD and session_ok(self.headers) is not True:
                self._json(401, {"error": "sesión no válida"})
                return

            if path == "/logout":
                tok = self.headers.get("X-Panel-Token", "")
                sessions.pop(tok, None)
                audit("logout")
                self._json(200, {"ok": True})
                return

            if path == "/api/ban":
                ip = valid_ip(body.get("ip"))
                secs = duration_secs(body.get("duration"))
                reason = clean_text(body.get("reason") or "manual desde el panel", 120)
                if not ip:
                    self._json(400, {"error": "IP inválida"})
                    return
                if not secs:
                    self._json(400, {"error": "duración inválida (máx 30 días, formatos 1h/4h/24h/7d/30d)"})
                    return
                wl_hit = ip_allowlisted(ip)
                code, resp = lapi_request("POST", "/v1/decisions",
                                          {"duration": "%ds" % secs, "scope": "ip", "value": ip,
                                           "type": "ban", "reason": reason})
                okk = code in (200, 201)
                audit("ban", {"ip": ip, "duracion_s": secs, "motivo": reason, "lapi": code}, ok=int(okk))
                if okk:
                    with STATE_LOCK:
                        counters["bans"] += 1
                self._json(200 if okk else code, {"ok": okk, "status": code,
                                                  "allowlisted": bool(wl_hit),
                                                  "warning": ("la IP está en tu allowlist (%s): el bouncer la ignorará" % wl_hit) if wl_hit else "",
                                                  "lapi": resp.decode("utf-8", "replace")[:300] if not okk else ""})
                return

            if path == "/api/unban":
                val = body.get("value")
                did = body.get("decision_id")
                if did is not None:
                    if not str(did).isdigit():
                        self._json(400, {"error": "decision_id inválido"})
                        return
                    qs = "?decision_id=" + str(did)
                else:
                    ip = valid_ip(val)
                    if not ip:
                        self._json(400, {"error": "IP o decision_id inválido"})
                        return
                    qs = "?scope=ip&value=" + urllib.parse.quote(ip, safe="")
                code, resp = lapi_request("DELETE", "/v1/decisions" + qs)
                okk = code in (200, 201, 204)
                audit("unban", {"qs": qs, "lapi": code}, ok=int(okk))
                if okk:
                    with STATE_LOCK:
                        counters["unbans"] += 1
                self._json(200 if okk else code, {"ok": okk, "status": code,
                                                  "lapi": resp.decode("utf-8", "replace")[:300] if not okk else ""})
                return

            if path == "/api/delete-alerts":
                ids = body.get("ids")
                if not isinstance(ids, list) or not ids or len(ids) > 200 or \
                        not all(isinstance(x, int) and 0 < x < 10 ** 12 for x in ids):
                    self._json(400, {"error": "ids inválidos (máx 200, enteros)"})
                    return
                qs = "?" + "&".join("alert_id=%d" % i for i in ids)
                code, resp = lapi_request("DELETE", "/v1/alerts" + qs)
                okk = code in (200, 201, 204)
                audit("delete-alerts", {"ids": ids, "lapi": code}, ok=int(okk))
                if okk:
                    with STATE_LOCK:
                        counters["deletes"] += len(ids)
                    with db() as c:
                        c.execute("DELETE FROM alerts WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)
                self._json(200 if okk else code, {"ok": okk, "status": code,
                                                  "lapi": resp.decode("utf-8", "replace")[:300] if not okk else ""})
                return

            if path == "/api/notifications-config":
                cfg = {"new_ban": 1 if body.get("new_ban") else 0,
                       "spike": int(body.get("spike") or 50),
                       "url": valid_notify_url(body.get("url"))}
                if body.get("url") and not cfg["url"]:
                    self._json(400, {"error": "URL inválida (solo http/https, uso LOCAL)"})
                    return
                cfg["spike"] = max(1, min(cfg["spike"], 100000))
                save_setting("notify", cfg)
                audit("notifications-config", cfg)
                self._json(200, {"ok": True, "cfg": cfg})
                return

            if path == "/api/notifications-test":
                add_notif("test", utcnow(), "Prueba de notificación",
                          "Si ves esto en tu destino, la integración funciona")
                self._json(200, {"ok": True})
                return

            self._json(404, {"error": "ruta no permitida"})
        except ValueError:
            self._json(400, {"error": "JSON inválido"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            try:
                self._json(500, {"error": "error interno del panel"})
            except Exception:
                pass

    def do_DELETE(self):
        self._json(405, {"error": "el panel usa POST /api/... para sus acciones"})

    do_PUT = do_DELETE
    do_PATCH = do_DELETE

    def log_message(self, fmt, *args):
        pass


def main():
    init_db()
    threading.Thread(target=poll_loop, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    modo = "con login" if UI_PASSWORD else "SIN contraseña (solo lectura)"
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Handler) as httpd:
        print("panel v%s: escuchando en 0.0.0.0:%d → LAPI %s (%s), datos en %s"
              % (VERSION, PORT, LAPI, modo, DB_PATH), flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
