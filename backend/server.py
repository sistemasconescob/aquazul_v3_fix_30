#!/usr/bin/env python3
"""
Aquazul Piscinas Sanas — Backend v3.1 Producción
- SQLite + WAL (soporte 1000 usuarios concurrentes)
- Autenticación JWT + rate limiting login
- Código OTP rotativo 45s para cambio de clave técnico
- Roles: admin / tecnico
- Upload fotos+videos hasta 100MB
- WhatsApp Business API
- Geocoding automático
"""
import sqlite3, json, hashlib, hmac, base64, os, sys, time, re
import threading, urllib.request, shutil, mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
import urllib.parse
from datetime import datetime, date
import uuid, math

# ─── CONFIG ───────────────────────────────────────────────────────────────────
# En Railway el working dir es /app, en local es relativo al script
_BASE    = os.path.dirname(os.path.abspath(__file__))
DB       = os.path.join(_BASE, "aquazul.db")
SECRET   = os.getenv("JWT_SECRET", "aquazul-super-secreto-cambia-esto-2024")
FRONTEND = os.path.abspath(os.path.join(_BASE, "..", "frontend"))
UPLOADS  = os.path.abspath(os.path.join(_BASE, "..", "frontend", "uploads"))
WA_TOKEN       = os.getenv("WA_TOKEN", "")
WA_PHONE_ID    = os.getenv("WA_PHONE_ID", "")
WA_API_VERSION = os.getenv("WA_API_VERSION", "v19.0")
APP_URL        = os.getenv("APP_URL", "http://localhost:8000")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "admin@aquazul.co")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin2024*")
OTP_INTERVAL   = 45  # segundos

os.makedirs(UPLOADS, exist_ok=True)

# ─── ESTADO EN MEMORIA ────────────────────────────────────────────────────────
ubicaciones      = {}
ubicaciones_lock = threading.Lock()

# Rate limiting login: {email: [timestamps]}
_login_attempts  = {}
_login_lock      = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW       = 300  # 5 minutos

# ─── DB ───────────────────────────────────────────────────────────────────────
_db_lock = threading.Lock()

def get_conn():
    c = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA busy_timeout = 15000")
    c.execute("PRAGMA cache_size = -16000")
    c.execute("PRAGMA synchronous = NORMAL")
    c.execute("PRAGMA temp_store = MEMORY")
    c.execute("PRAGMA mmap_size = 268435456")  # 256MB mmap
    return c

def q(sql, params=()):
    c = get_conn(); rows = c.execute(sql, params).fetchall(); c.close()
    return [dict(r) for r in rows]

def q1(sql, params=()):
    c = get_conn(); r = c.execute(sql, params).fetchone(); c.close()
    return dict(r) if r else None

def run(sql, params=()):
    max_retries = 5
    for attempt in range(max_retries):
        with _db_lock:
            c = get_conn()
            try:
                cur = c.execute(sql, params); c.commit(); lid = cur.lastrowid
                return lid
            except sqlite3.OperationalError as e:
                c.close()
                if "locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                raise
            except Exception:
                c.close()
                raise
    return None

def hash_pw(pw):
    return hashlib.sha256((pw + SECRET).encode()).hexdigest()

def make_token(uid, rol):
    payload = base64.b64encode(
        json.dumps({"sub": uid, "rol": rol, "exp": time.time() + 604800}).encode()
    ).decode()
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig

def verify_token(tok):
    try:
        payload, sig = tok.rsplit(".", 1)
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): return None
        data = json.loads(base64.b64decode(payload).decode())
        if data["exp"] < time.time(): return None
        return data
    except: return None

# ─── OTP ROTATIVO (45 segundos) ───────────────────────────────────────────────
def generate_otp():
    """Genera un código OTP de 6 dígitos que cambia cada 45 segundos"""
    slot = int(time.time()) // OTP_INTERVAL
    h = hashlib.sha256(f"{SECRET}:{slot}".encode()).hexdigest()
    code = str(int(h[:8], 16) % 1000000).zfill(6)
    return code

def verify_otp(code):
    """Verifica el OTP actual y el anterior (tolerancia de 1 slot)"""
    slot = int(time.time()) // OTP_INTERVAL
    for s in [slot, slot - 1]:
        h = hashlib.sha256(f"{SECRET}:{s}".encode()).hexdigest()
        valid = str(int(h[:8], 16) % 1000000).zfill(6)
        if hmac.compare_digest(code.strip(), valid):
            return True
    return False

def otp_seconds_remaining():
    """Segundos hasta que el OTP actual expire"""
    return OTP_INTERVAL - (int(time.time()) % OTP_INTERVAL)

# ─── RATE LIMITING LOGIN ──────────────────────────────────────────────────────
def check_rate_limit(email):
    """Retorna True si se puede intentar login, False si está bloqueado"""
    now = time.time()
    with _login_lock:
        attempts = _login_attempts.get(email, [])
        attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
        _login_attempts[email] = attempts
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            return False, int(LOGIN_WINDOW - (now - attempts[0]))
        return True, 0

def record_login_attempt(email):
    with _login_lock:
        _login_attempts.setdefault(email, []).append(time.time())

def clear_login_attempts(email):
    with _login_lock:
        _login_attempts.pop(email, None)

# ─── DB INIT + MIGRACIONES ────────────────────────────────────────────────────
def init_db():
    c = get_conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, rol TEXT NOT NULL CHECK(rol IN ('admin','tecnico')),
        telefono TEXT, activo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL, direccion TEXT NOT NULL,
        telefono TEXT, tipo_piscina TEXT NOT NULL,
        frecuencia TEXT NOT NULL, servicio_principal TEXT,
        lat REAL, lng REAL, notas TEXT, activo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS rutas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tecnico_id INTEGER NOT NULL REFERENCES usuarios(id),
        fecha TEXT NOT NULL, estado TEXT DEFAULT 'pendiente',
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS ruta_detalle (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ruta_id INTEGER NOT NULL REFERENCES rutas(id) ON DELETE CASCADE,
        cliente_id INTEGER NOT NULL REFERENCES clientes(id),
        orden INTEGER NOT NULL, estado TEXT DEFAULT 'pendiente',
        hora_inicio TEXT, hora_fin TEXT,
        lat_inicio REAL, lng_inicio REAL, lat_fin REAL, lng_fin REAL
    );
    CREATE TABLE IF NOT EXISTS reportes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ruta_detalle_id INTEGER REFERENCES ruta_detalle(id),
        cliente_id INTEGER NOT NULL REFERENCES clientes(id),
        tecnico_id INTEGER NOT NULL REFERENCES usuarios(id),
        fecha TEXT DEFAULT (datetime('now','localtime')),
        estado_servicio TEXT NOT NULL,
        actividades TEXT DEFAULT '[]',
        observaciones TEXT,
        evidencia_url TEXT, evidencia_url2 TEXT, evidencia_url3 TEXT, video_url TEXT
    );
    CREATE TABLE IF NOT EXISTS novedades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporte_id INTEGER REFERENCES reportes(id),
        cliente_id INTEGER NOT NULL REFERENCES clientes(id),
        tecnico_id INTEGER NOT NULL REFERENCES usuarios(id),
        tipo TEXT NOT NULL, descripcion TEXT NOT NULL,
        prioridad TEXT NOT NULL CHECK(prioridad IN ('baja','media','alta')),
        estado TEXT DEFAULT 'pendiente',
        evidencia_url TEXT, evidencia_url2 TEXT, video_url TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS ubicaciones_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tecnico_id INTEGER NOT NULL,
        lat REAL NOT NULL, lng REAL NOT NULL,
        timestamp TEXT DEFAULT (datetime('now','localtime'))
    );
    """)
    c.commit(); c.close()

    # Migraciones automáticas
    _migs = [
        ("novedades",    "evidencia_url2", "ALTER TABLE novedades ADD COLUMN evidencia_url2 TEXT"),
        ("novedades",    "video_url",      "ALTER TABLE novedades ADD COLUMN video_url TEXT"),
        ("clientes",     "lat",            "ALTER TABLE clientes ADD COLUMN lat REAL"),
        ("clientes",     "lng",            "ALTER TABLE clientes ADD COLUMN lng REAL"),
        ("clientes",     "notas",          "ALTER TABLE clientes ADD COLUMN notas TEXT"),
        ("ruta_detalle", "hora_inicio",    "ALTER TABLE ruta_detalle ADD COLUMN hora_inicio TEXT"),
        ("ruta_detalle", "hora_fin",       "ALTER TABLE ruta_detalle ADD COLUMN hora_fin TEXT"),
        ("ruta_detalle", "lat_inicio",     "ALTER TABLE ruta_detalle ADD COLUMN lat_inicio REAL"),
        ("ruta_detalle", "lng_inicio",     "ALTER TABLE ruta_detalle ADD COLUMN lng_inicio REAL"),
        ("reportes",     "evidencia_url2", "ALTER TABLE reportes ADD COLUMN evidencia_url2 TEXT"),
        ("reportes",     "evidencia_url3", "ALTER TABLE reportes ADD COLUMN evidencia_url3 TEXT"),
        ("reportes",     "video_url",      "ALTER TABLE reportes ADD COLUMN video_url TEXT"),
    ]
    with sqlite3.connect(DB) as mc:
        for tbl, col, sql in _migs:
            cols = [r[1] for r in mc.execute(f"PRAGMA table_info({tbl})").fetchall()]
            if col not in cols:
                try:
                    mc.execute(sql); mc.commit()
                    print(f"  [DB] Migración: {tbl}.{col} ✓")
                except Exception as e:
                    print(f"  [DB] Migración {tbl}.{col}: {e}")

    # Admin inicial
    if not q1("SELECT id FROM usuarios WHERE rol='admin' LIMIT 1"):
        run("INSERT INTO usuarios(nombre,email,password,rol,telefono) VALUES(?,?,?,?,?)",
            ("Administrador", ADMIN_EMAIL, hash_pw(ADMIN_PASSWORD), "admin", ""))
        print(f"  ✅ Admin creado: {ADMIN_EMAIL}")
    else:
        run("UPDATE usuarios SET password=?, email=? WHERE rol='admin'",
            (hash_pw(ADMIN_PASSWORD), ADMIN_EMAIL))
        print(f"  Admin actualizado: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")

# ─── WHATSAPP ─────────────────────────────────────────────────────────────────
def send_whatsapp(phone, message):
    if not WA_TOKEN or not WA_PHONE_ID:
        print(f"  [WA-SKIP] {phone}: {message[:50]}..."); return
    phone_clean = re.sub(r"[^\d]", "", phone)
    if len(phone_clean) == 10: phone_clean = "57" + phone_clean
    url = f"https://graph.facebook.com/{WA_API_VERSION}/{WA_PHONE_ID}/messages"
    payload = json.dumps({"messaging_product":"whatsapp","to":phone_clean,
                          "type":"text","text":{"body":message}}).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {WA_TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10): print(f"  [WA-OK] {phone_clean}")
    except Exception as e: print(f"  [WA-ERR] {e}")

def wa_bg(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()

def wa_asignacion(tec_nombre, clientes, fecha):
    fecha_fmt = datetime.strptime(fecha, "%Y-%m-%d").strftime("%d/%m/%Y") if "-" in fecha else fecha
    for c in clientes:
        if not c.get("telefono"): continue
        msg = (f"🌊 *Aquazul Piscinas Sanas*\n\nHola {c['nombre']}, programamos el mantenimiento de tu piscina:\n\n"
               f"📅 *Fecha:* {fecha_fmt}\n👨‍🔧 *Técnico:* {tec_nombre}\n\nRecibirás un mensaje cuando el técnico esté en camino.\n📞 Aquazul — Piscinas Sanas")
        send_whatsapp(c["telefono"], msg)

def wa_en_camino(tec_nombre, cliente, lat, lng):
    if not cliente.get("telefono"): return
    link = f"https://www.google.com/maps?q={lat},{lng}"
    msg = (f"🌊 *Aquazul Piscinas Sanas*\n\n🚗 *{tec_nombre} está en camino* a tu piscina!\n\n"
           f"📍 Ubicación actual:\n{link}\n\n¡Hasta pronto! 👋")
    send_whatsapp(cliente["telefono"], msg)

def wa_completado(tec_nombre, cliente, actividades, obs):
    if not cliente.get("telefono"): return
    acts = "\n".join([f"  ✓ {a}" for a in actividades]) if actividades else "  ✓ Mantenimiento general"
    obs_txt = f"\n📝 *Nota:* {obs}" if obs else ""
    msg = (f"🌊 *Aquazul Piscinas Sanas*\n\n✅ *Servicio completado*\n\n"
           f"Tu piscina fue atendida por *{tec_nombre}*.\n\n🔧 *Actividades:*\n{acts}{obs_txt}\n\n¡Tu piscina está lista! 🏊‍♂️")
    send_whatsapp(cliente["telefono"], msg)

# ─── UPLOAD ───────────────────────────────────────────────────────────────────
def save_upload(file_data, filename_hint="foto"):
    ext = os.path.splitext(filename_hint)[1].lower()
    allowed_img = {".jpg",".jpeg",".png",".webp",".heic",".gif"}
    allowed_vid = {".mp4",".mov",".webm",".3gp",".avi"}
    if ext not in allowed_img | allowed_vid: ext = ".jpg"
    name = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(UPLOADS, name), "wb") as f: f.write(file_data)
    return f"/uploads/{name}"

def parse_multipart(handler):
    ct = handler.headers.get("Content-Type", "")
    cl = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(cl)
    boundary = None
    for p in ct.split(";"):
        p = p.strip()
        if p.startswith("boundary="): boundary = p[9:].strip('"').encode(); break
    if not boundary: return {}, {}
    fields, files = {}, {}
    for part in body.split(b"--" + boundary)[1:]:
        if part in (b"", b"--\r\n", b"--") or part.startswith(b"--"): continue
        if b"\r\n\r\n" not in part: continue
        hdr_raw, _, body_part = part.partition(b"\r\n\r\n")
        body_part = body_part.rstrip(b"\r\n")
        hdr = hdr_raw.decode("utf-8", errors="replace")
        disp = ctype = ""
        for line in hdr.split("\r\n"):
            if line.lower().startswith("content-disposition:"): disp = line
            if line.lower().startswith("content-type:"): ctype = line.split(":",1)[1].strip()
        nm = re.search(r'name="([^"]*)"', disp)
        fn = re.search(r'filename="([^"]*)"', disp)
        if not nm: continue
        if fn: files[nm.group(1)] = {"data": body_part, "filename": fn.group(1), "content_type": ctype}
        else:  fields[nm.group(1)] = body_part.decode("utf-8", errors="replace")
    return fields, files

# ─── GEOCODING ────────────────────────────────────────────────────────────────
def geocode(direccion):
    try:
        q_str = urllib.parse.quote(direccion + ", Colombia")
        url = f"https://nominatim.openstreetmap.org/search?q={q_str}&format=json&limit=1"
        req = urllib.request.Request(url, headers={"User-Agent": "AquazulPiscinasSanas/3.1"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
            if data: return float(data[0]["lat"]), float(data[0]["lon"])
    except Exception as e: print(f"  [GEO] {e}")
    return None, None

# ─── HTTP HANDLER ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        status = args[1] if len(args) > 1 else "?"
        if sys.platform != "win32":
            c = "\033[32m" if str(status).startswith("2") else "\033[33m" if str(status).startswith("3") else "\033[31m"
            mc = "\033[93m" if self.command == "POST" else "\033[36m" if self.command in ("PUT","PATCH","DELETE") else ""
            print(f"  {mc}{self.command:7}\033[0m {self.path[:65]:65} {c}{status}\033[0m")
        else:
            print(f"  {self.command:7} {self.path[:65]:65} {status}")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Requested-With")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path):
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        ct = {"html":"text/html","js":"application/javascript","css":"text/css",
              "png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","webp":"image/webp",
              "svg":"image/svg+xml","ico":"image/x-icon","gif":"image/gif","heic":"image/heic",
              "mp4":"video/mp4","mov":"video/quicktime","webm":"video/webm",
              "3gp":"video/3gpp","avi":"video/x-msvideo"}.get(ext, "application/octet-stream")
        with open(path, "rb") as f: body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(body))
        if ext == "html":
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
        else:
            self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def read_json(self):
        try:
            l = int(self.headers.get("Content-Length", 0))
            if not l: return {}
            raw = self.rfile.read(l).decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
        except Exception as e:
            print(f"  [WARN] read_json: {e}"); return {}

    def get_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "): return verify_token(auth[7:])
        return None

    def require_auth(self, roles=None):
        user = self.get_user()
        if not user:
            self.send_json({"detail": "No autorizado"}, 401); return None
        if roles and user.get("rol") not in roles:
            self.send_json({"detail": "Sin permisos"}, 403); return None
        return user

    def route(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        method = self.command
        parts = [p for p in path.split("/") if p]

        # ── Archivos estáticos ──
        if path.startswith("/uploads/"):
            fpath = os.path.join(UPLOADS, os.path.basename(path))
            if os.path.isfile(fpath): self.send_file(fpath)
            else: self.send_json({"error": "No encontrado"}, 404)
            return

        if re.match(r"^/track(/\d+)?$", path):
            tp = os.path.join(FRONTEND, "track.html")
            if os.path.exists(tp): self.send_file(tp)
            else: self.send_json({"error": "No encontrado"}, 404)
            return

        if not path.startswith("/api"):
            candidate = os.path.join(FRONTEND, path.lstrip("/"))
            if os.path.isfile(candidate): self.send_file(candidate); return
            index = os.path.join(FRONTEND, "index.html")
            if os.path.exists(index): self.send_file(index)
            else: self.send_json({"error": "Frontend no encontrado"}, 404)
            return

        # ══════════════════════════════════════════════
        # API
        # ══════════════════════════════════════════════

        # ── HEALTH ──
        if path == "/api/health":
            self.send_json({"status":"ok","whatsapp":"ok" if WA_TOKEN else "no_configurado","version":"3.1.0"}); return

        # ── AUTH LOGIN ──
        if path == "/api/auth/login" and method == "POST":
            d = self.read_json()
            email_in = (d.get("email") or "").lower().strip()
            pass_in  = (d.get("password") or "")
            if not email_in or not pass_in:
                self.send_json({"detail": "Email y contraseña requeridos"}, 400); return
            # Rate limiting
            ok, wait = check_rate_limit(email_in)
            if not ok:
                self.send_json({"detail": f"Demasiados intentos. Espera {wait}s"}, 429); return
            u = q1("SELECT * FROM usuarios WHERE email=? COLLATE NOCASE AND activo=1", (email_in,))
            if not u:
                record_login_attempt(email_in)
                print(f"  [LOGIN] No encontrado: {email_in}")
                self.send_json({"detail": "Credenciales incorrectas"}, 401); return
            if u["password"] != hash_pw(pass_in):
                record_login_attempt(email_in)
                print(f"  [LOGIN] Contraseña incorrecta: {email_in}")
                self.send_json({"detail": "Credenciales incorrectas"}, 401); return
            clear_login_attempts(email_in)
            tok = make_token(u["id"], u["rol"])
            print(f"  [LOGIN] OK: {email_in} ({u['rol']})")
            self.send_json({"token": tok, "user": {
                "id": u["id"], "nombre": u["nombre"], "email": u["email"],
                "rol": u["rol"], "telefono": u["telefono"]
            }}); return

        # ── AUTH CAMBIAR CLAVE (usuario actual) ──
        if path == "/api/auth/cambiar-password" and method == "POST":
            user = self.require_auth()
            if not user: return
            d = self.read_json()
            u = q1("SELECT * FROM usuarios WHERE id=?", (user["sub"],))
            if not u or u["password"] != hash_pw(d.get("actual","")):
                self.send_json({"detail": "Contraseña actual incorrecta"}, 400); return
            nueva = (d.get("nueva") or "").strip()
            if len(nueva) < 6:
                self.send_json({"detail": "Mínimo 6 caracteres"}, 400); return
            run("UPDATE usuarios SET password=? WHERE id=?", (hash_pw(nueva), user["sub"]))
            self.send_json({"ok": True}); return

        # ── OTP: obtener código actual (solo admin) ──
        if path == "/api/otp/current" and method == "GET":
            user = self.require_auth(roles=["admin"])
            if not user: return
            self.send_json({
                "otp": generate_otp(),
                "seconds_remaining": otp_seconds_remaining(),
                "interval": OTP_INTERVAL
            }); return

        # ── CAMBIO CLAVE CON OTP (técnico se cambia su propia clave) ──
        if path == "/api/auth/cambiar-password-otp" and method == "POST":
            d = self.read_json()
            otp_code  = (d.get("otp") or "").strip()
            nueva     = (d.get("nueva") or "").strip()
            email_in  = (d.get("email") or "").lower().strip()
            if not otp_code or not nueva or not email_in:
                self.send_json({"detail": "OTP, email y nueva contraseña requeridos"}, 400); return
            if not verify_otp(otp_code):
                self.send_json({"detail": "Código OTP inválido o expirado"}, 401); return
            if len(nueva) < 6:
                self.send_json({"detail": "Mínimo 6 caracteres"}, 400); return
            u = q1("SELECT id FROM usuarios WHERE email=? COLLATE NOCASE AND activo=1", (email_in,))
            if not u:
                self.send_json({"detail": "Usuario no encontrado"}, 404); return
            run("UPDATE usuarios SET password=? WHERE id=?", (hash_pw(nueva), u["id"]))
            print(f"  [PWD-OTP] Clave actualizada: {email_in}")
            self.send_json({"ok": True}); return

        # ── UPLOAD ──
        if path == "/api/upload" and method == "POST":
            user = self.require_auth()
            if not user: return
            cl = int(self.headers.get("Content-Length", 0))
            if cl > 100 * 1024 * 1024:
                self.send_json({"detail": "Máx 100MB"}, 413); return
            ct = self.headers.get("Content-Type", "")
            if "multipart/form-data" in ct:
                fields, files = parse_multipart(self)
                fkey = next((k for k in ("file","foto","video") if k in files), None)
                if fkey:
                    f = files[fkey]
                    url = save_upload(f["data"], f["filename"])
                    self.send_json({"url": url, "ok": True}, 201)
                else:
                    self.send_json({"detail": "Campo 'file' requerido"}, 400)
            else:
                d = self.read_json()
                b64 = d.get("data","")
                if "," in b64: b64 = b64.split(",",1)[1]
                if not b64: self.send_json({"detail": "Sin datos"}, 400); return
                try:
                    url = save_upload(base64.b64decode(b64), "foto" + d.get("ext",".jpg"))
                    self.send_json({"url": url, "ok": True}, 201)
                except Exception as e:
                    self.send_json({"detail": str(e)}, 400)
            return

        # ── UBICACIÓN ──
        if path == "/api/ubicacion" and method == "POST":
            user = self.require_auth()
            if not user: return
            d = self.read_json()
            lat, lng = d.get("lat"), d.get("lng")
            if not lat or not lng: self.send_json({"detail": "lat y lng requeridos"}, 400); return
            tid = user["sub"]
            u_info = q1("SELECT nombre FROM usuarios WHERE id=?", (tid,))
            with ubicaciones_lock:
                ubicaciones[tid] = {"lat": lat, "lng": lng,
                    "timestamp": datetime.now().isoformat(),
                    "nombre": u_info["nombre"] if u_info else "Técnico"}
            run("INSERT INTO ubicaciones_log(tecnico_id,lat,lng) VALUES(?,?,?)", (tid, lat, lng))
            self.send_json({"ok": True}); return

        if path == "/api/ubicaciones" and method == "GET":
            cutoff = time.time() - 1800
            result = {}
            with ubicaciones_lock:
                for tid, info in ubicaciones.items():
                    try:
                        ts = datetime.fromisoformat(info["timestamp"]).timestamp()
                        if ts > cutoff: result[str(tid)] = info
                    except: pass
            self.send_json(result); return

        # ── DASHBOARD ──
        if path == "/api/dashboard" and method == "GET":
            stats = q1("""SELECT
                (SELECT COUNT(*) FROM reportes WHERE date(fecha)=date('now','localtime')) as servicios_hoy,
                (SELECT COUNT(*) FROM reportes WHERE date(fecha)=date('now','localtime') AND estado_servicio='finalizado') as finalizados_hoy,
                (SELECT COUNT(DISTINCT tecnico_id) FROM rutas WHERE fecha=date('now','localtime') AND estado='en_curso') as tecnicos_activos,
                (SELECT COUNT(*) FROM novedades WHERE estado='pendiente') as novedades_pendientes,
                (SELECT COUNT(*) FROM reportes WHERE strftime('%Y-%m',fecha)=strftime('%Y-%m','now','localtime')) as servicios_mes,
                (SELECT COUNT(*) FROM clientes WHERE activo=1) as total_clientes,
                (SELECT COUNT(*) FROM usuarios WHERE rol='tecnico' AND activo=1) as total_tecnicos
            """)
            rt = q1("""SELECT SUM(t) as total, SUM(c) as completados FROM (
                SELECT (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id) as t,
                       (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id AND rd.estado='finalizado') as c
                FROM rutas r WHERE r.fecha=date('now','localtime'))""")
            stats["rutas_hoy_total"] = rt["total"] or 0
            stats["rutas_hoy_completados"] = rt["completados"] or 0
            self.send_json(stats); return

        # ── CLIENTES ──
        if path == "/api/clientes":
            if method == "GET":
                self.send_json(q("SELECT * FROM clientes WHERE activo=1 ORDER BY nombre")); return
            if method == "POST":
                user = self.require_auth()
                if not user: return
                d = self.read_json()
                if not d.get("nombre") or not d.get("direccion"):
                    self.send_json({"detail": "Nombre y dirección requeridos"}, 400); return
                lat_c, lng_c = d.get("lat"), d.get("lng")
                if not lat_c or not lng_c:
                    lat_c, lng_c = geocode(d["direccion"])
                    if lat_c: print(f"  [GEO] {d['nombre']}: {lat_c:.5f}, {lng_c:.5f}")
                lid = run("INSERT INTO clientes(nombre,direccion,telefono,tipo_piscina,frecuencia,servicio_principal,lat,lng,notas) VALUES(?,?,?,?,?,?,?,?,?)",
                    (d["nombre"], d["direccion"], d.get("telefono",""), d.get("tipo_piscina","Residencial"),
                     d.get("frecuencia","Semanal"), d.get("servicio_principal",""), lat_c, lng_c, d.get("notas","")))
                self.send_json(q1("SELECT * FROM clientes WHERE id=?", (lid,)), 201); return

        if re.match(r"^/api/clientes/\d+$", path):
            cid = int(parts[-1])
            if method == "GET":
                c = q1("SELECT * FROM clientes WHERE id=?", (cid,))
                self.send_json(c or {"detail":"No encontrado"}, 200 if c else 404); return
            if method == "PUT":
                user = self.require_auth()
                if not user: return
                d = self.read_json()
                run("UPDATE clientes SET nombre=?,direccion=?,telefono=?,tipo_piscina=?,frecuencia=?,servicio_principal=?,notas=? WHERE id=?",
                    (d.get("nombre"), d.get("direccion"), d.get("telefono"), d.get("tipo_piscina"),
                     d.get("frecuencia"), d.get("servicio_principal"), d.get("notas",""), cid))
                self.send_json(q1("SELECT * FROM clientes WHERE id=?", (cid,))); return
            if method == "DELETE":
                user = self.require_auth()
                if not user: return
                run("UPDATE clientes SET activo=0 WHERE id=?", (cid,))
                self.send_json({"ok": True}); return

        if re.match(r"^/api/clientes/\d+/geocode$", path) and method == "POST":
            user = self.require_auth()
            if not user: return
            cid_g = int(parts[-2])
            cg = q1("SELECT id,nombre,direccion FROM clientes WHERE id=?", (cid_g,))
            if not cg: self.send_json({"detail":"No encontrado"},404); return
            lat_g, lng_g = geocode(cg["direccion"])
            if lat_g:
                run("UPDATE clientes SET lat=?,lng=? WHERE id=?", (lat_g, lng_g, cid_g))
                self.send_json({"ok":True,"lat":lat_g,"lng":lng_g}); return
            self.send_json({"detail":"No se pudo geocodificar"},400); return

        if re.match(r"^/api/clientes/\d+/historial$", path):
            cid = int(parts[-2])
            rows = q("""SELECT r.*,u.nombre as tecnico_nombre FROM reportes r
                JOIN usuarios u ON r.tecnico_id=u.id
                WHERE r.cliente_id=? ORDER BY r.fecha DESC LIMIT 30""", (cid,))
            self.send_json(rows); return

        # ── TÉCNICOS / USUARIOS ──
        if path == "/api/usuarios" and method == "GET":
            user = self.require_auth(roles=["admin"])
            if not user: return
            rol_f = qs.get("rol",[""])[0]
            sql = "SELECT id,nombre,email,telefono,rol,activo,created_at FROM usuarios WHERE activo=1"
            params = []
            if rol_f: sql += " AND rol=?"; params.append(rol_f)
            sql += " ORDER BY rol, nombre"
            todos = q(sql, params)
            for t in todos:
                if t["rol"] == "tecnico":
                    h = q1("""SELECT COUNT(*) as total,
                        SUM(CASE WHEN rd.estado='finalizado' THEN 1 ELSE 0 END) as completados
                        FROM rutas r JOIN ruta_detalle rd ON rd.ruta_id=r.id
                        WHERE r.tecnico_id=? AND r.fecha=date('now','localtime')""", (t["id"],))
                    t["servicios_hoy"] = {"total": h["total"] or 0, "completados": h["completados"] or 0}
                    with ubicaciones_lock: t["ubicacion"] = ubicaciones.get(t["id"])
                else:
                    t["servicios_hoy"] = None
                    t["ubicacion"] = None
            self.send_json(todos); return

        if path == "/api/tecnicos":
            if method == "GET":
                tecs = q("SELECT id,nombre,email,telefono,rol,activo,created_at FROM usuarios WHERE rol='tecnico' AND activo=1 ORDER BY nombre")
                for t in tecs:
                    h = q1("""SELECT COUNT(*) as total,
                        SUM(CASE WHEN rd.estado='finalizado' THEN 1 ELSE 0 END) as completados
                        FROM rutas r JOIN ruta_detalle rd ON rd.ruta_id=r.id
                        WHERE r.tecnico_id=? AND r.fecha=date('now','localtime')""", (t["id"],))
                    t["servicios_hoy"] = {"total": h["total"] or 0, "completados": h["completados"] or 0}
                    with ubicaciones_lock: t["ubicacion"] = ubicaciones.get(t["id"])
                self.send_json(tecs); return
            if method == "POST":
                user = self.require_auth(roles=["admin"])
                if not user: return
                d = self.read_json()
                if not d.get("nombre") or not d.get("email"):
                    self.send_json({"detail": "Nombre y email requeridos"}, 400); return
                rol = d.get("rol","tecnico")
                if rol not in ("admin","tecnico"):
                    self.send_json({"detail": "Rol inválido. Use 'admin' o 'tecnico'"}, 400); return
                pw = d.get("password","Tecnico2024*")
                if len(pw.strip()) < 6:
                    self.send_json({"detail": "Contraseña mínimo 6 caracteres"}, 400); return
                try:
                    lid = run("INSERT INTO usuarios(nombre,email,password,rol,telefono) VALUES(?,?,?,?,?)",
                        (d["nombre"], d["email"].lower().strip(), hash_pw(pw), rol, d.get("telefono","")))
                    self.send_json(q1("SELECT id,nombre,email,telefono,rol FROM usuarios WHERE id=?", (lid,)), 201)
                except:
                    self.send_json({"detail": "Email ya registrado"}, 400)
                return

        # Cambiar clave por admin (directo, sin OTP)
        if re.match(r"^/api/tecnicos/\d+/password$", path) and method == "PATCH":
            user = self.require_auth(roles=["admin"])
            if not user: return
            uid = int(parts[-2])
            d = self.read_json()
            new_pass = (d.get("password") or "").strip()
            if len(new_pass) < 6:
                self.send_json({"detail": "Mínimo 6 caracteres"}, 400); return
            run("UPDATE usuarios SET password=? WHERE id=?", (hash_pw(new_pass), uid))
            print(f"  [PWD] Clave actualizada uid={uid}")
            self.send_json({"ok": True}); return

        if re.match(r"^/api/tecnicos/\d+$", path):
            tid2 = int(parts[-1])
            if method == "GET":
                t = q1("SELECT id,nombre,email,telefono,rol FROM usuarios WHERE id=?", (tid2,))
                self.send_json(t or {"detail":"No encontrado"}, 200 if t else 404); return
            if method == "PUT":
                user = self.require_auth(roles=["admin"])
                if not user: return
                d = self.read_json()
                run("UPDATE usuarios SET nombre=?,telefono=?,email=? WHERE id=?",
                    (d.get("nombre"), d.get("telefono"), d.get("email","").lower().strip(), tid2))
                self.send_json({"ok": True}); return
            if method == "DELETE":
                user = self.require_auth(roles=["admin"])
                if not user: return
                run("UPDATE usuarios SET activo=0 WHERE id=?", (tid2,))
                self.send_json({"ok": True}); return

        # ── RUTAS ──
        if path == "/api/rutas/hoy":
            rows = q("""SELECT r.*,u.nombre as tecnico_nombre,
                (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id) as total,
                (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id AND rd.estado='finalizado') as completados
                FROM rutas r JOIN usuarios u ON r.tecnico_id=u.id
                WHERE r.fecha=date('now','localtime') ORDER BY u.nombre""")
            self.send_json(rows); return

        if re.match(r"^/api/rutas/tecnico/\d+/hoy$", path):
            tid2 = int(parts[-2])
            ruta = (q1("SELECT * FROM rutas WHERE tecnico_id=? AND fecha=date('now','localtime')", (tid2,)) or
                    q1("SELECT * FROM rutas WHERE tecnico_id=? AND estado IN ('pendiente','en_curso') ORDER BY fecha DESC LIMIT 1", (tid2,)) or
                    q1("SELECT * FROM rutas WHERE tecnico_id=? AND fecha>=date('now','-7 days','localtime') ORDER BY fecha DESC LIMIT 1", (tid2,)))
            if not ruta: self.send_json({"ruta": None, "detalles": []}); return
            dets = q("""SELECT rd.*,c.nombre as cliente_nombre,c.direccion,c.tipo_piscina,
                c.servicio_principal,c.lat,c.lng,c.telefono as cliente_telefono,c.notas as cliente_notas
                FROM ruta_detalle rd JOIN clientes c ON rd.cliente_id=c.id
                WHERE rd.ruta_id=? ORDER BY rd.orden""", (ruta["id"],))
            self.send_json({"ruta": ruta, "detalles": dets}); return

        if path == "/api/rutas":
            if method == "GET":
                fecha_f = qs.get("fecha",[""])[0]
                tid_f   = qs.get("tecnico_id",[""])[0]
                sql = """SELECT r.*,u.nombre as tecnico_nombre,
                    (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id) as total,
                    (SELECT COUNT(*) FROM ruta_detalle rd WHERE rd.ruta_id=r.id AND rd.estado='finalizado') as completados
                    FROM rutas r JOIN usuarios u ON r.tecnico_id=u.id WHERE 1=1"""
                params = []
                if fecha_f: sql += " AND r.fecha=?"; params.append(fecha_f)
                if tid_f:   sql += " AND r.tecnico_id=?"; params.append(int(tid_f))
                sql += " ORDER BY r.fecha DESC LIMIT 100"
                self.send_json(q(sql, params)); return
            if method == "POST":
                user = self.require_auth(roles=["admin"])
                if not user: return
                d = self.read_json()
                if not d.get("tecnico_id") or not d.get("fecha"):
                    self.send_json({"detail": "tecnico_id y fecha requeridos"}, 400); return
                ex = q1("SELECT id FROM rutas WHERE tecnico_id=? AND fecha=?", (d["tecnico_id"], d["fecha"]))
                if ex: self.send_json({"detail": "Ya existe una ruta para este técnico en esa fecha"}, 400); return
                rid = run("INSERT INTO rutas(tecnico_id,fecha,estado) VALUES(?,?,'pendiente')", (d["tecnico_id"], d["fecha"]))
                clientes_ruta = []
                for cl in d.get("clientes", []):
                    run("INSERT INTO ruta_detalle(ruta_id,cliente_id,orden,estado) VALUES(?,?,?,'pendiente')",
                        (rid, cl["cliente_id"], cl["orden"]))
                    ci = q1("SELECT id,nombre,telefono FROM clientes WHERE id=?", (cl["cliente_id"],))
                    if ci: ci["orden"] = cl["orden"]; clientes_ruta.append(ci)
                tec = q1("SELECT nombre FROM usuarios WHERE id=?", (d["tecnico_id"],))
                if tec and clientes_ruta:
                    wa_bg(wa_asignacion, tec["nombre"], clientes_ruta, d["fecha"])
                ruta_full = q1("SELECT r.*,u.nombre as tecnico_nombre FROM rutas r JOIN usuarios u ON r.tecnico_id=u.id WHERE r.id=?", (rid,))
                dets = q("SELECT rd.*,c.nombre as cliente_nombre FROM ruta_detalle rd JOIN clientes c ON rd.cliente_id=c.id WHERE rd.ruta_id=? ORDER BY rd.orden", (rid,))
                self.send_json({**ruta_full, "detalles": dets}, 201); return

        if re.match(r"^/api/rutas/\d+$", path):
            rid = int(parts[-1])
            if method == "GET":
                ruta = q1("SELECT r.*,u.nombre as tecnico_nombre FROM rutas r JOIN usuarios u ON r.tecnico_id=u.id WHERE r.id=?", (rid,))
                if not ruta: self.send_json({"detail":"No encontrada"},404); return
                dets = q("SELECT rd.*,c.nombre as cliente_nombre,c.direccion,c.tipo_piscina,c.lat,c.lng FROM ruta_detalle rd JOIN clientes c ON rd.cliente_id=c.id WHERE rd.ruta_id=? ORDER BY rd.orden", (rid,))
                self.send_json({**ruta, "detalles": dets}); return
            if method == "DELETE":
                user = self.require_auth(roles=["admin"])
                if not user: return
                run("DELETE FROM rutas WHERE id=?", (rid,))
                self.send_json({"ok": True}); return

        if re.match(r"^/api/rutas/detalle/\d+/estado$", path):
            did = int(parts[-2])
            d = self.read_json()
            nuevo = d.get("estado")
            run("""UPDATE ruta_detalle SET estado=?,
                hora_inicio=COALESCE(?,hora_inicio), hora_fin=COALESCE(?,hora_fin),
                lat_inicio=COALESCE(?,lat_inicio), lng_inicio=COALESCE(?,lng_inicio)
                WHERE id=?""",
                (nuevo, d.get("hora_inicio"), d.get("hora_fin"), d.get("lat"), d.get("lng"), did))
            det_info = q1("SELECT ruta_id FROM ruta_detalle WHERE id=?", (did,))
            if det_info:
                rid = det_info["ruta_id"]
                total = q1("SELECT COUNT(*) as n FROM ruta_detalle WHERE ruta_id=?", (rid,))
                fin   = q1("SELECT COUNT(*) as n FROM ruta_detalle WHERE ruta_id=? AND estado='finalizado'", (rid,))
                nuevo_er = 'completada' if (fin and total and fin['n']==total['n'] and total['n']>0) else 'en_curso'
                run("UPDATE rutas SET estado=? WHERE id=?", (nuevo_er, rid))
            if nuevo == "en_proceso":
                det = q1("""SELECT rd.*,c.nombre as cliente_nombre,c.telefono as cliente_telefono,c.id as cliente_id,
                    u.nombre as tecnico_nombre FROM ruta_detalle rd JOIN clientes c ON rd.cliente_id=c.id
                    JOIN rutas r ON rd.ruta_id=r.id JOIN usuarios u ON r.tecnico_id=u.id WHERE rd.id=?""", (did,))
                if det:
                    cli = {"telefono": det.get("cliente_telefono"), "id": det.get("cliente_id")}
                    wa_bg(wa_en_camino, det["tecnico_nombre"], cli, d.get("lat",-4.8087), d.get("lng",-75.6906))
            self.send_json({"ok": True}); return

        # ── REPORTES ──
        if path == "/api/reportes":
            if method == "GET":
                tid_f = qs.get("tecnico_id",[""])[0]
                cid_f = qs.get("cliente_id",[""])[0]
                limit = int(qs.get("limit",["50"])[0])
                sql = """SELECT r.*,u.nombre as tecnico_nombre,c.nombre as cliente_nombre
                    FROM reportes r JOIN usuarios u ON r.tecnico_id=u.id
                    JOIN clientes c ON r.cliente_id=c.id WHERE 1=1"""
                params = []
                if tid_f: sql += " AND r.tecnico_id=?"; params.append(int(tid_f))
                if cid_f: sql += " AND r.cliente_id=?"; params.append(int(cid_f))
                sql += f" ORDER BY r.fecha DESC LIMIT {limit}"
                self.send_json(q(sql, params)); return
            if method == "POST":
                user = self.require_auth()
                if not user: return
                d = self.read_json()
                if not d.get("cliente_id") or not d.get("tecnico_id") or not d.get("estado_servicio"):
                    self.send_json({"detail": "cliente_id, tecnico_id y estado_servicio requeridos"}, 400); return
                acts = json.dumps(d.get("actividades", []), ensure_ascii=False)
                lid = run("""INSERT INTO reportes(ruta_detalle_id,cliente_id,tecnico_id,estado_servicio,
                    actividades,observaciones,evidencia_url,evidencia_url2,evidencia_url3,video_url)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (d.get("ruta_detalle_id"), d["cliente_id"], d["tecnico_id"],
                     d["estado_servicio"], acts, d.get("observaciones",""),
                     d.get("evidencia_url"), d.get("evidencia_url2"), d.get("evidencia_url3"), d.get("video_url")))
                if d.get("ruta_detalle_id"):
                    run("UPDATE ruta_detalle SET estado=?,hora_fin=time('now') WHERE id=?",
                        (d["estado_servicio"], d["ruta_detalle_id"]))
                if d["estado_servicio"] == "finalizado":
                    cli = q1("SELECT nombre,telefono FROM clientes WHERE id=?", (d["cliente_id"],))
                    tec = q1("SELECT nombre FROM usuarios WHERE id=?", (d["tecnico_id"],))
                    if cli and tec:
                        wa_bg(wa_completado, tec["nombre"], cli, d.get("actividades",[]), d.get("observaciones",""))
                self.send_json({"id": lid, "ok": True}, 201); return

        if re.match(r"^/api/reportes/\d+$", path):
            rid = int(parts[-1])
            r = q1("""SELECT r.*,u.nombre as tecnico_nombre,c.nombre as cliente_nombre
                FROM reportes r JOIN usuarios u ON r.tecnico_id=u.id
                JOIN clientes c ON r.cliente_id=c.id WHERE r.id=?""", (rid,))
            self.send_json(r or {"detail":"No encontrado"}, 200 if r else 404); return

        # ── NOVEDADES ──
        if path == "/api/novedades":
            if method == "GET":
                estado_f = qs.get("estado",[""])[0]
                prio_f   = qs.get("prioridad",[""])[0]
                sql = """SELECT n.*,u.nombre as tecnico_nombre,c.nombre as cliente_nombre
                    FROM novedades n JOIN usuarios u ON n.tecnico_id=u.id
                    JOIN clientes c ON n.cliente_id=c.id WHERE 1=1"""
                params = []
                if estado_f: sql += " AND n.estado=?"; params.append(estado_f)
                if prio_f:   sql += " AND n.prioridad=?"; params.append(prio_f)
                sql += " ORDER BY CASE n.prioridad WHEN 'alta' THEN 1 WHEN 'media' THEN 2 ELSE 3 END, n.created_at DESC"
                self.send_json(q(sql, params)); return
            if method == "POST":
                user = self.require_auth()
                if not user: return
                d = self.read_json()
                if not d.get("cliente_id") or not d.get("tecnico_id") or not d.get("tipo") or not d.get("descripcion"):
                    self.send_json({"detail": "cliente_id, tecnico_id, tipo y descripcion requeridos"}, 400); return
                prio = d.get("prioridad","media")
                if prio not in ("baja","media","alta"):
                    self.send_json({"detail": "prioridad debe ser baja, media o alta"}, 400); return
                lid = run("""INSERT INTO novedades(reporte_id,cliente_id,tecnico_id,tipo,descripcion,prioridad,evidencia_url,evidencia_url2,video_url)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (d.get("reporte_id"), d["cliente_id"], d["tecnico_id"],
                     d["tipo"], d["descripcion"], prio,
                     d.get("evidencia_url"), d.get("evidencia_url2"), d.get("video_url")))
                self.send_json({"id": lid, "ok": True}, 201); return

        if re.match(r"^/api/novedades/\d+/estado$", path):
            nid = int(parts[-2])
            d = self.read_json()
            run("UPDATE novedades SET estado=? WHERE id=?", (d.get("estado","gestionado"), nid))
            self.send_json({"ok": True}); return

        if re.match(r"^/api/novedades/\d+$", path):
            nid = int(parts[-1])
            row = q1("""SELECT n.*,u.nombre as tecnico_nombre,c.nombre as cliente_nombre
                FROM novedades n JOIN usuarios u ON n.tecnico_id=u.id
                JOIN clientes c ON n.cliente_id=c.id WHERE n.id=?""", (nid,))
            self.send_json(row or {"detail":"No encontrado"}, 200 if row else 404); return

        # ── WHATSAPP TEST ──
        if path == "/api/whatsapp/test" and method == "POST":
            user = self.require_auth(roles=["admin"])
            if not user: return
            d = self.read_json()
            wa_bg(send_whatsapp, d.get("phone",""), d.get("message","Test Aquazul"))
            self.send_json({"ok": True}); return

        self.send_json({"detail": "Endpoint no encontrado"}, 404)

    def do_GET(self):    self.route()
    def do_POST(self):   self.route()
    def do_PUT(self):    self.route()
    def do_PATCH(self):  self.route()
    def do_DELETE(self): self.route()

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", sys.argv[1] if len(sys.argv) > 1 else "8000"))
    init_db()
    wa_st = "OK" if WA_TOKEN else "NO configurado (ver .env)"
    print("")
    print("  AQUAZUL PISCINAS SANAS  -  v3.1 Prod")
    print("  " + "="*40)
    print(f"  URL:       http://localhost:{port}")
    print(f"  WhatsApp:  {wa_st}")
    print(f"  Health:    http://localhost:{port}/api/health")
    print(f"  OTP panel: http://localhost:{port} → Admin → Técnicos")
    print("")
    print(f"  Admin:     {ADMIN_EMAIL}")
    print(f"  Password:  {ADMIN_PASSWORD}")
    print("")
    print("  Ctrl+C para detener")
    print("  " + "="*40)
    print("")
    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True  # mata threads al cerrar el server

    server = ThreadedHTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido")
