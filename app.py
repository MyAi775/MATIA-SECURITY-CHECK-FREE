import os
import re
import json
import hmac
import time
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    render_template_string,
    abort,
)
from werkzeug.middleware.proxy_fix import ProxyFix


# ============================================================
# MATIA // SECURITY CHECK
# Full Flask Application
# ============================================================

APP_NAME = "MATIA // SECURITY CHECK"
APP_VERSION = "3.0.0"

STATUSES = [
    "PENDING",
    "ACCEPTED",
    "DECLINED",
    "IN PROGRESS",
    "COMPLETED",
]

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "MATIA_DB_PATH",
    os.path.join(BASE_DIR, "matia_security.db"),
)

SECRET_KEY = os.environ.get("MATIA_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

OWNER_EMAIL = os.environ.get("MATIA_OWNER_EMAIL", "")
OWNER_PASSWORD = os.environ.get("MATIA_OWNER_PASSWORD", "")

ADMIN_EMAIL = os.environ.get("MATIA_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")

COOKIE_SECURE = (
    os.environ.get("MATIA_COOKIE_SECURE", "true").lower()
    in ("1", "true", "yes", "on")
)


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
)


# ============================================================
# HELPERS
# ============================================================

START_TIME = time.time()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def uptime_seconds():
    return int(time.time() - START_TIME)


def safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clean_text(value, max_length=2000):
    if value is None:
        return ""

    value = str(value).strip()

    if len(value) > max_length:
        value = value[:max_length]

    return value


def valid_email(value):
    if not value:
        return False

    value = value.strip()

    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value,
        )
    )


def valid_target(value):
    if not value:
        return False

    value = value.strip()

    if len(value) > 500:
        return False

    if " " in value:
        return False

    if value.startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)

            if not parsed.netloc:
                return False

            return True

        except Exception:
            return False

    if re.fullmatch(
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        value,
    ):
        return True

    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        value,
    ):
        return True

    if value in ("localhost", "127.0.0.1"):
        return True

    return False


def safe_next(value, fallback="/admin"):
    if not value:
        return fallback

    if not value.startswith("/"):
        return fallback

    if value.startswith("//"):
        return fallback

    return value


def role():
    return session.get("role")


def current_role():
    return role()


def is_staff():
    return role() in ("admin", "owner")


def is_owner():
    return role() == "owner"


# ============================================================
# DATABASE
# ============================================================

def db():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass

    return connection


def init_db():
    connection = db()

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_token TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            web_name TEXT NOT NULL,
            target TEXT NOT NULL,
            scope TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            client_ip TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            audience TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_requests_status
        ON requests(status);

        CREATE INDEX IF NOT EXISTS idx_messages_request
        ON messages(request_id);

        CREATE INDEX IF NOT EXISTS idx_findings_request
        ON findings(request_id);

        CREATE INDEX IF NOT EXISTS idx_notifications_audience
        ON notifications(audience);

        CREATE INDEX IF NOT EXISTS idx_audit_created
        ON audit_log(created_at);
        """
    )

    connection.commit()
    connection.close()


def query_one(sql, params=()):
    connection = db()

    row = connection.execute(
        sql,
        params,
    ).fetchone()

    connection.close()

    return row


def query_all(sql, params=()):
    connection = db()

    rows = connection.execute(
        sql,
        params,
    ).fetchall()

    connection.close()

    return rows


def execute(sql, params=()):
    connection = db()

    cursor = connection.execute(
        sql,
        params,
    )

    connection.commit()

    last_id = cursor.lastrowid

    connection.close()

    return last_id


# ============================================================
# AUDIT / NOTIFICATIONS
# ============================================================

def audit_action(actor, action, details=""):
    try:
        execute(
            """
            INSERT INTO audit_log
            (actor, action, details, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                clean_text(actor, 100),
                clean_text(action, 300),
                clean_text(details, 2000),
                now(),
            ),
        )
    except Exception:
        pass


def notify(
    audience,
    kind,
    title,
    body,
    request_id=None,
):
    return execute(
        """
        INSERT INTO notifications
        (request_id, audience, kind, title, body, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            audience,
            clean_text(kind, 100),
            clean_text(title, 200),
            clean_text(body, 1000),
            now(),
        ),
    )


def system_message(request_id, message):
    execute(
        """
        INSERT INTO messages
        (request_id, sender, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            "SYSTEM",
            clean_text(message, 4000),
            now(),
        ),
    )


# ============================================================
# REQUEST HELPERS
# ============================================================

def get_request(request_id):
    return query_one(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,),
    )


def get_request_by_token(request_id, token):
    return query_one(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        AND client_token = ?
        """,
        (
            request_id,
            token,
        ),
    )


def stats():
    rows = query_all(
        """
        SELECT status, COUNT(*) AS total
        FROM requests
        GROUP BY status
        """
    )

    result = {
        "PENDING": 0,
        "ACCEPTED": 0,
        "DECLINED": 0,
        "IN PROGRESS": 0,
        "COMPLETED": 0,
    }

    for row in rows:
        result[row["status"]] = row["total"]

    result["TOTAL"] = sum(result.values())

    return result


# ============================================================
# AUTH DECORATORS
# ============================================================

def role_required(required_role):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):

            if role() != required_role:
                return render_template_string(
                    ERROR_403,
                    app_name=APP_NAME,
                ), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


def staff_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if role() not in ("admin", "owner"):
            return render_template_string(
                ERROR_403,
                app_name=APP_NAME,
            ), 403

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "media-src 'self' data:;"
    )

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# ============================================================
# ERROR PAGES
# ============================================================

ERROR_403 = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>403 // ACCESS DENIED</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    background:#020303;
    color:#00ff9c;
    font-family:Consolas,monospace;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
}
.box{
    width:min(700px,92%);
    border:1px solid #00ff9c;
    background:#050909;
    padding:40px;
    box-shadow:
        0 0 25px rgba(0,255,156,.15),
        inset 0 0 30px rgba(0,255,156,.03);
}
.code{
    font-size:72px;
    font-weight:900;
}
h1{
    color:#fff;
}
p{
    color:#9fb5ac;
}
a{
    color:#00ff9c;
}
</style>
</head>
<body>
<div class="box">
    <div class="code">403</div>
    <h1>// ACCESS DENIED</h1>
    <p>
        Your current session does not have permission
        to access this node.
    </p>
    <p>
        <a href="/">RETURN TO MAIN SYSTEM</a>
    </p>
</div>
</body>
</html>
"""


# ============================================================
# PUBLIC HOME
# ============================================================

HOME_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ app_name }}</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    background:#020303;
    color:#d8fff0;
    font-family:Inter,Arial,sans-serif;
}
body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    background:
      linear-gradient(rgba(0,255,156,.025) 1px,transparent 1px),
      linear-gradient(90deg,rgba(0,255,156,.025) 1px,transparent 1px);
    background-size:40px 40px;
}
.nav{
    padding:18px 6%;
    border-bottom:1px solid #123a2c;
    display:flex;
    justify-content:space-between;
    align-items:center;
}
.logo{
    color:#00ff9c;
    font-weight:900;
    letter-spacing:2px;
}
.nav a{
    color:#9cb8ad;
    text-decoration:none;
    margin-left:20px;
}
.nav a:hover{
    color:#00ff9c;
}
.hero{
    width:min(1100px,90%);
    margin:70px auto;
}
.badge{
    color:#00ff9c;
    font-family:monospace;
}
h1{
    font-size:clamp(42px,7vw,85px);
    margin:15px 0;
    color:white;
}
h1 span{
    color:#00ff9c;
}
.sub{
    color:#91aaa0;
    max-width:700px;
    line-height:1.7;
}
.grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
    gap:18px;
    margin-top:45px;
}
.card{
    padding:25px;
    background:#060b09;
    border:1px solid #123a2c;
    border-radius:14px;
}
.card b{
    color:#00ff9c;
}
.actions{
    display:flex;
    gap:12px;
    flex-wrap:wrap;
    margin-top:35px;
}
.btn{
    padding:13px 20px;
    border-radius:8px;
    border:1px solid #00ff9c;
    color:#00ff9c;
    text-decoration:none;
    font-weight:800;
}
.btn.primary{
    background:#00ff9c;
    color:#001b11;
}
</style>
</head>
<body>

<nav class="nav">
    <div class="logo">MATIA // SECURITY CHECK</div>
    <div>
        <a href="/how-it-works">How it works</a>
        <a href="/admin/login">Staff</a>
    </div>
</nav>

<section class="hero">

<div class="badge">[ AUTHORIZED SECURITY ASSESSMENT PLATFORM ]</div>

<h1>SECURE.<br><span>TEST.</span><br>REPORT.</h1>

<p class="sub">
Submit an authorized security assessment request.
Track its status and communicate with the security team
from one protected dashboard.
</p>

<div class="actions">
    <a class="btn primary" href="/request">REQUEST ASSESSMENT</a>
    <a class="btn" href="/admin/login">STAFF LOGIN</a>
</div>

<div class="grid">
    <div class="card">
        <b>01 // REQUEST</b>
        <p>Submit target, scope and contact information.</p>
    </div>

    <div class="card">
        <b>02 // REVIEW</b>
        <p>Authorized staff reviews and accepts the request.</p>
    </div>

    <div class="card">
        <b>03 // TEST</b>
        <p>Security testing is performed within the approved scope.</p>
    </div>

    <div class="card">
        <b>04 // REPORT</b>
        <p>Findings and recommendations are delivered through the dashboard.</p>
    </div>
</div>

</section>
</body>
</html>
"""


@app.get("/")
def home():
    return render_template_string(
        HOME_PAGE,
        app_name=APP_NAME,
    )


# ============================================================
# HOW IT WORKS
# ============================================================

HOW_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>How it works</title>
<style>
body{
    margin:0;
    background:#020303;
    color:#dffff2;
    font-family:Arial,sans-serif;
}
.wrap{
    width:min(900px,92%);
    margin:60px auto;
}
h1{
    color:#00ff9c;
}
.box{
    margin:18px 0;
    padding:24px;
    background:#060b09;
    border:1px solid #123a2c;
    border-radius:12px;
}
a{
    color:#00ff9c;
}
</style>
</head>
<body>
<div class="wrap">
<h1>// HOW IT WORKS</h1>

<div class="box">
<b>01 — REQUEST</b>
<p>Submit your target and the exact authorized scope.</p>
</div>

<div class="box">
<b>02 — REVIEW</b>
<p>Staff reviews the request.</p>
</div>

<div class="box">
<b>03 — ACCEPT</b>
<p>Once accepted, the client dashboard activates live communication.</p>
</div>

<div class="box">
<b>04 — ASSESSMENT</b>
<p>Testing is performed only against authorized targets and scope.</p>
</div>

<div class="box">
<b>05 — REPORT</b>
<p>Findings, evidence and recommendations become available.</p>
</div>

<p><a href="/">← Back</a></p>
</div>
</body>
</html>
"""


@app.get("/how-it-works")
def how_it_works():
    return render_template_string(HOW_PAGE)


# ============================================================
# REQUEST FORM
# ============================================================

REQUEST_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>New Request</title>
<style>
body{
    margin:0;
    background:#020303;
    color:#dffff2;
    font-family:Arial,sans-serif;
}
.wrap{
    width:min(760px,92%);
    margin:50px auto;
}
h1{
    color:#00ff9c;
}
.panel{
    background:#050a08;
    border:1px solid #123a2c;
    border-radius:14px;
    padding:30px;
}
label{
    display:block;
    margin:18px 0 7px;
    color:#9fb8ae;
}
input,textarea{
    width:100%;
    padding:13px;
    border-radius:8px;
    border:1px solid #174a36;
    background:#020504;
    color:white;
    outline:none;
}
input:focus,textarea:focus{
    border-color:#00ff9c;
}
textarea{
    min-height:130px;
    resize:vertical;
}
button{
    margin-top:22px;
    padding:14px 22px;
    background:#00ff9c;
    color:#00170e;
    border:0;
    border-radius:8px;
    font-weight:900;
    cursor:pointer;
}
.note{
    color:#80998f;
    font-size:13px;
}
a{
    color:#00ff9c;
}
</style>
</head>
<body>
<div class="wrap">
<h1>// NEW SECURITY REQUEST</h1>

<div class="panel">

<form method="post">

<label>Name</label>
<input name="name" maxlength="100" required>

<label>Email</label>
<input name="email" type="email" maxlength="200" required>

<label>Website / Project Name</label>
<input name="web_name" maxlength="200" required>

<label>Target</label>
<input
    name="target"
    maxlength="500"
    placeholder="example.com"
    required
>

<label>Authorized Scope</label>
<textarea
    name="scope"
    maxlength="4000"
    placeholder="Describe exactly what is authorized..."
    required
></textarea>

<p class="note">
Only submit systems you own or have explicit authorization to test.
</p>

<button type="submit">SUBMIT REQUEST</button>

</form>

<p><a href="/">← Back</a></p>

</div>
</div>
</body>
</html>
"""


@app.route("/request", methods=["GET", "POST"])
def request_page():

    if request.method == "GET":
        return render_template_string(REQUEST_PAGE)

    name = clean_text(request.form.get("name"), 100)
    email = clean_text(request.form.get("email"), 200)
    web_name = clean_text(request.form.get("web_name"), 200)
    target = clean_text(request.form.get("target"), 500)
    scope = clean_text(request.form.get("scope"), 4000)

    if not name or not valid_email(email):
        return "Invalid name or email", 400

    if not web_name:
        return "Website/project name is required", 400

    if not valid_target(target):
        return "Invalid target", 400

    if not scope:
        return "Scope is required", 400

    token = secrets.token_urlsafe(32)
    timestamp = now()

    request_id = execute(
        """
        INSERT INTO requests
        (
            client_token,
            name,
            email,
            web_name,
            target,
            scope,
            status,
            created_at,
            updated_at,
            client_ip
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token,
            name,
            email,
            web_name,
            target,
            scope,
            "PENDING",
            timestamp,
            timestamp,
            request.remote_addr or "",
        ),
    )

    system_message(
        request_id,
        "Request created. Waiting for staff review.",
    )

    notify(
        "staff",
        "new_request",
        "NEW SECURITY REQUEST",
        f"{name} submitted request #{request_id}.",
        request_id,
    )

    audit_action(
        "CLIENT",
        "request_created",
        f"request_id={request_id}",
    )

    return redirect(
        url_for(
            "client_status",
            request_id=request_id,
            token=token,
        )
    )


# ============================================================
# CLIENT STATUS
# ============================================================

STATUS_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Client Dashboard</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    background:#020303;
    color:#dffff2;
    font-family:Arial,sans-serif;
}
.wrap{
    width:min(1100px,94%);
    margin:35px auto;
}
.top{
    display:flex;
    justify-content:space-between;
    gap:15px;
    align-items:center;
    flex-wrap:wrap;
}
.logo{
    color:#00ff9c;
    font-family:monospace;
    font-weight:900;
}
button{
    background:#07120d;
    color:#00ff9c;
    border:1px solid #00ff9c;
    border-radius:7px;
    padding:10px 14px;
    cursor:pointer;
}
.panel{
    margin-top:20px;
    padding:22px;
    background:#050a08;
    border:1px solid #123a2c;
    border-radius:14px;
}
.status{
    font-size:25px;
    color:#00ff9c;
    font-weight:900;
}
.meta{
    color:#8fa99f;
    line-height:1.8;
}
.chat{
    height:360px;
    overflow-y:auto;
    padding:15px;
    background:#010403;
    border:1px solid #123a2c;
    border-radius:10px;
}
.msg{
    margin:9px 0;
    padding:10px 12px;
    border-left:3px solid #123a2c;
    background:#050a08;
}
.msg.staff{
    border-left-color:#00ff9c;
}
.msg.system{
    border-left-color:#ffe45c;
}
.sender{
    color:#00ff9c;
    font-family:monospace;
    font-size:12px;
}
.time{
    color:#60776e;
    font-size:11px;
}
.compose{
    display:flex;
    gap:8px;
    margin-top:10px;
}
.compose input{
    flex:1;
    padding:12px;
    background:#020504;
    color:white;
    border:1px solid #174a36;
    border-radius:7px;
}
.hidden{
    display:none;
}
.finding{
    padding:15px;
    margin:10px 0;
    border:1px solid #173d30;
    border-radius:8px;
}
</style>
</head>

<body>

<div class="wrap">

<div class="top">
<div class="logo">MATIA // CLIENT NODE #{{ request_id }}</div>

<button onclick="enableRing()">
🔔 ENABLE RING
</button>
</div>

<div class="panel">
<div>STATUS</div>
<div class="status" id="status">LOADING...</div>

<div class="meta">
<div>Target: <span id="target">...</span></div>
<div>Project: <span id="web_name">...</span></div>
<div>Updated: <span id="updated">...</span></div>
</div>
</div>

<div class="panel">
<h2>// LIVE CHAT</h2>

<div id="chat" class="chat"></div>

<div class="compose">
<input
    id="message"
    maxlength="4000"
    placeholder="Type message..."
>
<button onclick="sendMessage()">SEND</button>
</div>
</div>

<div class="panel">
<h2>// FINDINGS</h2>
<div id="findings">No findings yet.</div>
</div>

<div class="panel">
<h2>// REPORT</h2>
<a
    id="reportLink"
    href="/report/{{ request_id }}?token={{ token }}"
    style="color:#00ff9c"
>
OPEN SECURITY REPORT
</a>
</div>

</div>

<script>

const requestId = {{ request_id|tojson }};
const token = {{ token|tojson }};

let lastMessageId = 0;
let lastFindingId = 0;
let audioCtx = null;
let ringEnabled = localStorage.getItem("matia_ring") === "1";

async function enableRing(){

    try{

        if("Notification" in window){
            await Notification.requestPermission();
        }

        const AudioContext =
            window.AudioContext ||
            window.webkitAudioContext;

        if(AudioContext){

            if(!audioCtx){
                audioCtx = new AudioContext();
            }

            if(audioCtx.state === "suspended"){
                await audioCtx.resume();
            }

            playRing();
        }

        localStorage.setItem("matia_ring","1");
        ringEnabled = true;

        alert("Ring enabled.");

    }catch(e){

        console.error(e);

        alert(
            "Browser blocked audio. Click the button again."
        );
    }
}


function playRing(){

    if(!ringEnabled || !audioCtx){
        return;
    }

    try{

        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();

        osc.type = "sine";
        osc.frequency.value = 880;

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        const t = audioCtx.currentTime;

        gain.gain.setValueAtTime(0.0001,t);
        gain.gain.exponentialRampToValueAtTime(
            0.18,
            t + 0.03
        );

        gain.gain.exponentialRampToValueAtTime(
            0.0001,
            t + 0.35
        );

        osc.start(t);
        osc.stop(t + 0.4);

    }catch(e){}
}


function browserNotify(title,body){

    if(
        "Notification" in window &&
        Notification.permission === "granted"
    ){

        try{

            new Notification(
                title,
                {
                    body:body,
                    tag:"matia-security-check"
                }
            );

        }catch(e){}
    }
}


function notifyEvent(title,body){

    if(ringEnabled){
        playRing();
    }

    browserNotify(title,body);
}


function escapeHtml(value){

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


async function loadData(){

    try{

        const response = await fetch(
            `/api/client/${requestId}/data?token=${encodeURIComponent(token)}`,
            {
                cache:"no-store"
            }
        );

        if(!response.ok){
            return;
        }

        const data = await response.json();

        document.getElementById("status").textContent =
            data.request.status;

        document.getElementById("target").textContent =
            data.request.target;

        document.getElementById("web_name").textContent =
            data.request.web_name;

        document.getElementById("updated").textContent =
            data.request.updated_at;

        const chat = document.getElementById("chat");

        let html = "";

        for(const msg of data.messages){

            const cls =
                msg.sender === "SYSTEM"
                    ? "system"
                    : msg.sender === "STAFF"
                        ? "staff"
                        : "";

            html += `
                <div class="msg ${cls}">
                    <div class="sender">
                        ${escapeHtml(msg.sender)}
                    </div>

                    <div>
                        ${escapeHtml(msg.message)}
                    </div>

                    <div class="time">
                        ${escapeHtml(msg.created_at)}
                    </div>
                </div>
            `;

            if(
                lastMessageId &&
                msg.id > lastMessageId &&
                msg.sender === "STAFF"
            ){

                notifyEvent(
                    "MATIA // STAFF MESSAGE",
                    msg.message
                );
            }
        }

        if(data.messages.length){
            lastMessageId =
                data.messages[data.messages.length - 1].id;
        }

        chat.innerHTML =
            html || "<div>No messages yet.</div>";

        chat.scrollTop = chat.scrollHeight;

        const findings =
            document.getElementById("findings");

        if(!data.findings.length){

            findings.innerHTML =
                "No findings yet.";

        }else{

            let fh = "";

            for(const finding of data.findings){

                fh += `
                    <div class="finding">
                        <b>
                            ${escapeHtml(finding.title)}
                        </b>

                        <div>
                            Severity:
                            ${escapeHtml(finding.severity)}
                        </div>

                        <p>
                            ${escapeHtml(finding.description)}
                        </p>
                    </div>
                `;

                if(
                    lastFindingId &&
                    finding.id > lastFindingId
                ){

                    notifyEvent(
                        "NEW SECURITY FINDING",
                        finding.title
                    );
                }
            }

            lastFindingId =
                data.findings[data.findings.length - 1].id;

            findings.innerHTML = fh;
        }

    }catch(e){

        console.error(e);

    }
}


async function sendMessage(){

    const input =
        document.getElementById("message");

    const message =
        input.value.trim();

    if(!message){
        return;
    }

    input.value = "";

    try{

        const response = await fetch(
            `/api/client/${requestId}/message`,
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({
                    token:token,
                    message:message
                })
            }
        );

        if(response.ok){
            await loadData();
        }

    }catch(e){
        console.error(e);
    }
}


document
    .getElementById("message")
    .addEventListener(
        "keydown",
        function(event){

            if(event.key === "Enter"){
                sendMessage();
            }

        }
    );


loadData();

setInterval(
    loadData,
    1000
);

</script>

</body>
</html>
"""


@app.get("/status/<int:request_id>")
def client_status(request_id):

    token = request.args.get("token", "")

    item = get_request_by_token(
        request_id,
        token,
    )

    if not item:
        return render_template_string(
            ERROR_403,
            app_name=APP_NAME,
        ), 403

    return render_template_string(
        STATUS_PAGE,
        request_id=request_id,
        token=token,
        app_name=APP_NAME,
    )


# ============================================================
# CLIENT API
# ============================================================

@app.get("/api/client/<int:request_id>/data")
def client_data(request_id):

    token = request.args.get("token", "")

    item = get_request_by_token(
        request_id,
        token,
    )

    if not item:
        return jsonify(
            {
                "error": "access_denied"
            }
        ), 403

    messages = query_all(
        """
        SELECT id, sender, message, created_at
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    findings = query_all(
        """
        SELECT
            id,
            title,
            severity,
            description,
            evidence,
            recommendation,
            created_at
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    return jsonify(
        {
            "request": dict(item),
            "messages": [dict(x) for x in messages],
            "findings": [dict(x) for x in findings],
        }
    )


@app.post("/api/client/<int:request_id>/message")
def client_message(request_id):

    data = request.get_json(silent=True) or {}

    token = clean_text(data.get("token"), 300)
    message = clean_text(data.get("message"), 4000)

    item = get_request_by_token(
        request_id,
        token,
    )

    if not item:
        return jsonify(
            {
                "error": "access_denied"
            }
        ), 403

    if item["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
    ):
        return jsonify(
            {
                "error": "chat_not_active"
            }
        ), 400

    if not message:
        return jsonify(
            {
                "error": "message_required"
            }
        ), 400

    execute(
        """
        INSERT INTO messages
        (request_id, sender, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            "CLIENT",
            message,
            now(),
        ),
    )

    notify(
        "staff",
        "client_message",
        "NEW CLIENT MESSAGE",
        f"Client sent a message on request #{request_id}.",
        request_id,
    )

    return jsonify(
        {
            "ok": True
        }
    )


# ============================================================
# REPORT
# ============================================================

REPORT_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Report</title>
<style>
body{
    margin:0;
    background:#020303;
    color:#e4fff5;
    font-family:Arial,sans-serif;
}
.wrap{
    width:min(1000px,94%);
    margin:40px auto;
}
.header{
    border-bottom:1px solid #173d30;
    padding-bottom:20px;
}
.green{
    color:#00ff9c;
}
.card{
    margin:18px 0;
    padding:20px;
    background:#050a08;
    border:1px solid #173d30;
    border-radius:10px;
}
.sev{
    color:#00ff9c;
    font-family:monospace;
}
pre{
    white-space:pre-wrap;
    color:#a8c0b6;
}
</style>
</head>
<body>

<div class="wrap">

<div class="header">
<h1 class="green">
MATIA // SECURITY ASSESSMENT REPORT
</h1>

<p>
Request #{{ item.id }}
</p>

<p>
Target:
<strong>{{ item.target }}</strong>
</p>

<p>
Status:
<strong>{{ item.status }}</strong>
</p>
</div>

<h2>Findings</h2>

{% if findings %}

{% for finding in findings %}

<div class="card">

<h3>{{ finding.title }}</h3>

<div class="sev">
Severity: {{ finding.severity }}
</div>

<p>{{ finding.description }}</p>

<h4>Evidence</h4>
<pre>{{ finding.evidence }}</pre>

<h4>Recommendation</h4>
<p>{{ finding.recommendation }}</p>

</div>

{% endfor %}

{% else %}

<div class="card">
No findings have been published yet.
</div>

{% endif %}

</div>

</body>
</html>
"""


@app.get("/report/<int:request_id>")
def report(request_id):

    token = request.args.get("token", "")

    item = get_request_by_token(
        request_id,
        token,
    )

    if not item:
        return render_template_string(
            ERROR_403,
            app_name=APP_NAME,
        ), 403

    findings = query_all(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    return render_template_string(
        REPORT_PAGE,
        item=item,
        findings=findings,
    )


# ============================================================
# LOGIN
# ============================================================

LOGIN_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#010202;
    color:#dffff2;
    font-family:Consolas,monospace;
}
.box{
    width:min(440px,92%);
    background:#050a08;
    border:1px solid #00ff9c;
    padding:32px;
    border-radius:14px;
    box-shadow:0 0 35px rgba(0,255,156,.08);
}
.logo{
    color:#00ff9c;
    font-size:24px;
    font-weight:900;
}
.sub{
    color:#718b80;
    margin-bottom:25px;
}
label{
    display:block;
    margin:14px 0 7px;
}
input{
    width:100%;
    padding:13px;
    background:#020403;
    color:white;
    border:1px solid #174a36;
    border-radius:7px;
}
button{
    width:100%;
    padding:13px;
    margin-top:20px;
    background:#00ff9c;
    color:#00160d;
    border:0;
    border-radius:7px;
    font-weight:900;
    cursor:pointer;
}
.error{
    padding:10px;
    background:#210808;
    border:1px solid #ff5555;
    color:#ff8888;
    margin-bottom:15px;
}
a{
    color:#00ff9c;
}
</style>
</head>

<body>

<div class="box">

<div class="logo">MATIA // SECURITY</div>

<p class="sub">
{{ title }}
</p>

{% if error %}
<div class="error">
{{ error }}
</div>
{% endif %}

<form method="post">

<input
    type="hidden"
    name="next"
    value="{{ next_url }}"
>

<label>Email</label>

<input
    type="email"
    name="email"
    autocomplete="username"
    required
>

<label>Password</label>

<input
    type="password"
    name="password"
    autocomplete="current-password"
    required
>

<button type="submit">
AUTHENTICATE
</button>

</form>

<p style="margin-top:20px">
<a href="/">← Main system</a>
</p>

</div>

</body>
</html>
"""


def credentials_match(email, password, expected_email, expected_password):

    if not expected_email or not expected_password:
        return False

    try:

        return (
            hmac.compare_digest(
                email,
                expected_email,
            )
            and
            hmac.compare_digest(
                password,
                expected_password,
            )
        )

    except Exception:

        return False


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    next_url = safe_next(
        request.args.get(
            "next",
            request.form.get("next", "/admin"),
        ),
        "/admin",
    )

    if role() == "admin":
        return redirect(next_url)

    if role() == "owner":
        return redirect("/owner")

    error = ""

    if request.method == "POST":

        email = clean_text(
            request.form.get("email"),
            200,
        )

        password = request.form.get(
            "password",
            "",
        )

        if credentials_match(
            email,
            password,
            ADMIN_EMAIL,
            ADMIN_PASSWORD,
        ):

            session.clear()

            session["role"] = "admin"
            session["email"] = email
            session["login_at"] = now()

            audit_action(
                email,
                "admin_login",
            )

            return redirect(next_url)

        error = "Invalid admin credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="ADMIN AUTHENTICATION",
        error=error,
        next_url=next_url,
    )


@app.route("/owner/login", methods=["GET", "POST"])
def owner_login():

    next_url = safe_next(
        request.args.get(
            "next",
            request.form.get("next", "/owner"),
        ),
        "/owner",
    )

    if role() == "owner":
        return redirect(next_url)

    error = ""

    if request.method == "POST":

        email = clean_text(
            request.form.get("email"),
            200,
        )

        password = request.form.get(
            "password",
            "",
        )

        if credentials_match(
            email,
            password,
            OWNER_EMAIL,
            OWNER_PASSWORD,
        ):

            session.clear()

            session["role"] = "owner"
            session["email"] = email
            session["login_at"] = now()

            audit_action(
                email,
                "owner_login",
            )

            return redirect(next_url)

        error = "Invalid owner credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="OWNER AUTHENTICATION",
        error=error,
        next_url=next_url,
    )


@app.get("/logout")
def logout():

    actor = session.get("email", "UNKNOWN")

    audit_action(
        actor,
        "logout",
    )

    session.clear()

    return redirect("/")


# ============================================================
# STAFF CSS
# ============================================================

STAFF_STYLE = """
<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at top right,
            rgba(0,255,156,.06),
            transparent 35%
        ),
        #010202;
    color:#dffff2;
    font-family:Inter,Arial,sans-serif;
}

body:before{
    content:"";
    position:fixed;
    inset:0;
    pointer-events:none;
    opacity:.18;
    background:
        linear-gradient(
            rgba(0,255,156,.025) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(0,255,156,.025) 1px,
            transparent 1px
        );
    background-size:35px 35px;
}

.nav{
    position:sticky;
    top:0;
    z-index:20;
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:15px 24px;
    background:rgba(2,5,4,.94);
    backdrop-filter:blur(10px);
    border-bottom:1px solid #123a2c;
}

.logo{
    color:#00ff9c;
    font-family:Consolas,monospace;
    font-weight:900;
    letter-spacing:1px;
}

.navlinks{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
}

.navlinks a,
.navlinks button{
    color:#9ebbb0;
    text-decoration:none;
    background:#07100c;
    border:1px solid #153e2e;
    padding:8px 12px;
    border-radius:7px;
    cursor:pointer;
}

.navlinks a:hover,
.navlinks button:hover{
    color:#00ff9c;
    border-color:#00ff9c;
}

.container{
    width:min(1450px,96%);
    margin:25px auto;
}

.grid{
    display:grid;
    grid-template-columns:
        repeat(auto-fit,minmax(190px,1fr));
    gap:14px;
}

.card{
    background:rgba(4,10,8,.94);
    border:1px solid #123a2c;
    border-radius:12px;
    padding:18px;
}

.stat{
    font-size:30px;
    font-weight:900;
    color:#00ff9c;
}

.muted{
    color:#718b80;
}

.table-wrap{
    overflow:auto;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    padding:12px;
    border-bottom:1px solid #123024;
    text-align:left;
    white-space:nowrap;
}

th{
    color:#00ff9c;
    font-family:Consolas,monospace;
}

tr:hover{
    background:#06100c;
}

.badge{
    padding:5px 8px;
    border-radius:6px;
    border:1px solid #174a36;
    color:#00ff9c;
    font-family:Consolas,monospace;
    font-size:12px;
}

.btn{
    display:inline-block;
    padding:8px 11px;
    border-radius:7px;
    border:1px solid #174a36;
    background:#07100c;
    color:#00ff9c;
    text-decoration:none;
    cursor:pointer;
}

.btn:hover{
    border-color:#00ff9c;
}

.danger{
    color:#ff7777;
    border-color:#552525;
}

input,
textarea,
select{
    width:100%;
    background:#020403;
    color:#e8fff5;
    border:1px solid #174a36;
    border-radius:7px;
    padding:11px;
}

textarea{
    min-height:100px;
    resize:vertical;
}

button{
    font:inherit;
}

.form-row{
    display:grid;
    grid-template-columns:
        repeat(auto-fit,minmax(220px,1fr));
    gap:12px;
}

.form-group{
    margin-bottom:12px;
}

label{
    display:block;
    color:#8da89d;
    margin-bottom:6px;
}

.chat{
    height:430px;
    overflow-y:auto;
    background:#010302;
    border:1px solid #123a2c;
    border-radius:10px;
    padding:15px;
}

.message{
    margin:8px 0;
    padding:10px 12px;
    background:#06100c;
    border-left:3px solid #1b4937;
}

.message.client{
    border-left-color:#00ff9c;
}

.message.system{
    border-left-color:#ffe45c;
}

.sender{
    color:#00ff9c;
    font-family:Consolas,monospace;
    font-size:12px;
}

.time{
    color:#5c746b;
    font-size:11px;
}

.compose{
    display:flex;
    gap:8px;
    margin-top:10px;
}

.compose input{
    flex:1;
}

.terminal{
    background:#010302;
    border:1px solid #00ff9c;
    border-radius:10px;
    padding:15px;
    box-shadow:
        inset 0 0 35px rgba(0,255,156,.03),
        0 0 25px rgba(0,255,156,.05);
}

.terminal-output{
    height:430px;
    overflow:auto;
    white-space:pre-wrap;
    font-family:Consolas,monospace;
    color:#7dffc2;
}

.terminal-input{
    display:flex;
    gap:8px;
    margin-top:10px;
}

.terminal-input input{
    font-family:Consolas,monospace;
}

.notification{
    position:fixed;
    right:20px;
    bottom:20px;
    z-index:99;
    width:min(380px,90%);
    padding:15px;
    background:#06100c;
    border:1px solid #00ff9c;
    border-radius:10px;
    display:none;
}

@media(max-width:700px){
    .nav{
        align-items:flex-start;
        gap:12px;
        flex-direction:column;
    }
}

</style>
"""


# ============================================================
# STAFF JAVASCRIPT
# ============================================================

STAFF_JS = """
<script>

let audioCtx = null;

let ringEnabled =
    localStorage.getItem("matia_ring") === "1";

let notificationCursor =
    Number(
        localStorage.getItem(
            "matia_notification_cursor"
        ) || "0"
    );


async function enableRing(){

    try{

        if("Notification" in window){
            await Notification.requestPermission();
        }

        const AC =
            window.AudioContext ||
            window.webkitAudioContext;

        if(AC){

            if(!audioCtx){
                audioCtx = new AC();
            }

            if(audioCtx.state === "suspended"){
                await audioCtx.resume();
            }

            playRing();
        }

        localStorage.setItem(
            "matia_ring",
            "1"
        );

        ringEnabled = true;

        showToast(
            "RING ENABLED",
            "Browser notifications and sound are enabled."
        );

    }catch(error){

        console.error(error);

        showToast(
            "RING ERROR",
            "Browser audio permission was not granted."
        );
    }
}


function playRing(){

    if(!ringEnabled || !audioCtx){
        return;
    }

    try{

        const osc =
            audioCtx.createOscillator();

        const gain =
            audioCtx.createGain();

        osc.type = "square";
        osc.frequency.value = 900;

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        const t =
            audioCtx.currentTime;

        gain.gain.setValueAtTime(
            0.0001,
            t
        );

        gain.gain.exponentialRampToValueAtTime(
            0.13,
            t + .03
        );

        gain.gain.exponentialRampToValueAtTime(
            0.0001,
            t + .35
        );

        osc.start(t);
        osc.stop(t + .4);

    }catch(error){}
}


function browserNotify(title,body){

    if(
        "Notification" in window &&
        Notification.permission === "granted"
    ){

        try{

            new Notification(
                title,
                {
                    body:body,
                    tag:"matia-security-check"
                }
            );

        }catch(error){}
    }
}


function eventNotify(title,body){

    playRing();
    browserNotify(title,body);
}


function showToast(title,body){

    const box =
        document.getElementById("notification");

    if(!box){
        return;
    }

    box.innerHTML =
        `<b>${escapeHtml(title)}</b>
         <div style="margin-top:5px">
         ${escapeHtml(body)}
         </div>`;

    box.style.display = "block";

    setTimeout(
        () => {
            box.style.display = "none";
        },
        5000
    );
}


function escapeHtml(value){

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


async function pollNotifications(){

    try{

        const response =
            await fetch(
                `/api/staff/notifications?after=${notificationCursor}`,
                {
                    cache:"no-store"
                }
            );

        if(!response.ok){
            return;
        }

        const data =
            await response.json();

        for(const item of data.notifications){

            notificationCursor =
                Math.max(
                    notificationCursor,
                    item.id
                );

            eventNotify(
                item.title,
                item.body
            );

            showToast(
                item.title,
                item.body
            );
        }

        localStorage.setItem(
            "matia_notification_cursor",
            String(notificationCursor)
        );

    }catch(error){

        console.error(error);
    }
}


setInterval(
    pollNotifications,
    1000
);

pollNotifications();

</script>
"""


# ============================================================
# STAFF DASHBOARD
# ============================================================

STAFF_DASHBOARD = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
""" + STAFF_STYLE + """
</head>

<body>

<div class="nav">

<div class="logo">
MATIA // {{ role_name|upper }} CONTROL
</div>

<div class="navlinks">

<a href="{{ dashboard_url }}">Dashboard</a>

{% if role_name == "owner" %}
<a href="/owner/terminal">Terminal</a>
{% endif %}

<button onclick="enableRing()">
🔔 ENABLE RING
</button>

<a href="/logout">
Logout
</a>

</div>

</div>

<div class="container">

<div class="card">

<h1>
// {{ role_name|upper }} DASHBOARD
</h1>

<p class="muted">
Authenticated as {{ email }}
</p>

</div>

<div class="grid" style="margin-top:15px">

<div class="card">
<div class="muted">TOTAL</div>
<div class="stat">{{ stats.TOTAL }}</div>
</div>

<div class="card">
<div class="muted">PENDING</div>
<div class="stat">{{ stats.PENDING }}</div>
</div>

<div class="card">
<div class="muted">ACCEPTED</div>
<div class="stat">{{ stats.ACCEPTED }}</div>
</div>

<div class="card">
<div class="muted">IN PROGRESS</div>
<div class="stat">{{ stats["IN PROGRESS"] }}</div>
</div>

<div class="card">
<div class="muted">COMPLETED</div>
<div class="stat">{{ stats.COMPLETED }}</div>
</div>

<div class="card">
<div class="muted">DECLINED</div>
<div class="stat">{{ stats.DECLINED }}</div>
</div>

</div>

<div class="card" style="margin-top:15px">

<h2>// CLIENT REQUESTS</h2>

<div class="table-wrap">

<table>

<thead>

<tr>
<th>ID</th>
<th>NAME</th>
<th>EMAIL</th>
<th>PROJECT</th>
<th>TARGET</th>
<th>STATUS</th>
<th>UPDATED</th>
<th>ACTION</th>
</tr>

</thead>

<tbody>

{% for item in requests %}

<tr>

<td>#{{ item.id }}</td>

<td>{{ item.name }}</td>

<td>{{ item.email }}</td>

<td>{{ item.web_name }}</td>

<td>{{ item.target }}</td>

<td>
<span class="badge">
{{ item.status }}
</span>
</td>

<td>{{ item.updated_at }}</td>

<td>
<a
    class="btn"
    href="/admin/client/{{ item.id }}"
>
OPEN
</a>
</td>

</tr>

{% else %}

<tr>
<td colspan="8">
No requests.
</td>
</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</div>

<div id="notification" class="notification"></div>

""" + STAFF_JS + """

<script>

setTimeout(
    () => location.reload(),
    15000
);

</script>

</body>
</html>
"""


@app.get("/admin")
@staff_required
def admin_dashboard():

    items = query_all(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    )

    return render_template_string(
        STAFF_DASHBOARD,
        title="Staff Dashboard",
        role_name=current_role(),
        email=session.get("email", ""),
        stats=stats(),
        requests=items,
        dashboard_url="/owner" if is_owner() else "/admin",
        app_name=APP_NAME,
    )


@app.get("/owner")
@role_required("owner")
def owner_dashboard():

    items = query_all(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    )

    return render_template_string(
        STAFF_DASHBOARD,
        title="Owner Dashboard",
        role_name="owner",
        email=session.get("email", ""),
        stats=stats(),
        requests=items,
        dashboard_url="/owner",
        app_name=APP_NAME,
    )


# ============================================================
# STAFF CLIENT DETAIL
# ============================================================

STAFF_DETAIL = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Client #{{ item.id }}</title>
""" + STAFF_STYLE + """
</head>

<body>

<div class="nav">

<div class="logo">
MATIA // CLIENT #{{ item.id }}
</div>

<div class="navlinks">

<a href="{{ dashboard_url }}">
Dashboard
</a>

<button onclick="enableRing()">
🔔 ENABLE RING
</button>

<a href="/logout">
Logout
</a>

</div>

</div>

<div class="container">

<div class="grid">

<div class="card">
<div class="muted">CLIENT</div>
<h2>{{ item.name }}</h2>
<p>{{ item.email }}</p>
</div>

<div class="card">
<div class="muted">PROJECT</div>
<h2>{{ item.web_name }}</h2>
<p>{{ item.target }}</p>
</div>

<div class="card">
<div class="muted">STATUS</div>
<h2 id="status">{{ item.status }}</h2>
</div>

</div>

<div class="card" style="margin-top:15px">

<h2>// CONTROL</h2>

<div class="form-row">

<button
class="btn"
onclick="setStatus('ACCEPTED')"
>
ACCEPT
</button>

<button
class="btn danger"
onclick="setStatus('DECLINED')"
>
DECLINE
</button>

<button
class="btn"
onclick="setStatus('IN PROGRESS')"
>
START
</button>

<button
class="btn"
onclick="setStatus('COMPLETED')"
>
COMPLETE
</button>

<button
class="btn"
onclick="setStatus('PENDING')"
>
REOPEN
</button>

</div>

</div>

<div class="card" style="margin-top:15px">

<h2>// AUTHORIZED SCOPE</h2>

<pre style="white-space:pre-wrap;color:#9eb8ae">
{{ item.scope }}
</pre>

</div>

<div class="card" style="margin-top:15px">

<h2>// LIVE CHAT</h2>

<div id="chat" class="chat"></div>

<div class="compose">

<input
id="message"
maxlength="4000"
placeholder="Message client..."
>

<button
class="btn"
onclick="sendMessage()"
>
SEND
</button>

</div>

</div>

<div class="card" style="margin-top:15px">

<h2>// ADD FINDING</h2>

<form onsubmit="addFinding(event)">

<div class="form-group">
<label>Title</label>
<input
id="finding_title"
maxlength="300"
required
>
</div>

<div class="form-group">
<label>Severity</label>

<select id="finding_severity">

<option>INFO</option>
<option>LOW</option>
<option>MEDIUM</option>
<option>HIGH</option>
<option>CRITICAL</option>

</select>

</div>

<div class="form-group">
<label>Description</label>
<textarea
id="finding_description"
maxlength="5000"
required
></textarea>
</div>

<div class="form-group">
<label>Evidence</label>
<textarea
id="finding_evidence"
maxlength="8000"
required
></textarea>
</div>

<div class="form-group">
<label>Recommendation</label>
<textarea
id="finding_recommendation"
maxlength="5000"
required
></textarea>
</div>

<button class="btn" type="submit">
ADD FINDING
</button>

</form>

</div>

<div class="card" style="margin-top:15px">

<h2>// FINDINGS</h2>

<div id="findings">
Loading...
</div>

</div>

<div id="notification" class="notification"></div>

</div>

""" + STAFF_JS + """

<script>

const requestId =
    {{ item.id|tojson }};

let lastMessageId = 0;
let firstLoad = true;


function escapeHtml(value){

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


async function loadClient(){

    try{

        const response =
            await fetch(
                `/api/staff/client/${requestId}/data`,
                {
                    cache:"no-store"
                }
            );

        if(!response.ok){
            return;
        }

        const data =
            await response.json();

        document.getElementById("status")
            .textContent =
                data.request.status;

        const chat =
            document.getElementById("chat");

        let html = "";

        for(const msg of data.messages){

            let cls = "";

            if(msg.sender === "CLIENT"){
                cls = "client";
            }

            if(msg.sender === "SYSTEM"){
                cls = "system";
            }

            html += `
                <div class="message ${cls}">
                    <div class="sender">
                        ${escapeHtml(msg.sender)}
                    </div>

                    <div>
                        ${escapeHtml(msg.message)}
                    </div>

                    <div class="time">
                        ${escapeHtml(msg.created_at)}
                    </div>
                </div>
            `;

            if(
                !firstLoad &&
                lastMessageId &&
                msg.id > lastMessageId &&
                msg.sender === "CLIENT"
            ){

                eventNotify(
                    "NEW CLIENT MESSAGE",
                    msg.message
                );

                showToast(
                    "NEW CLIENT MESSAGE",
                    msg.message
                );
            }
        }

        if(data.messages.length){

            lastMessageId =
                data.messages[
                    data.messages.length - 1
                ].id;
        }

        chat.innerHTML =
            html || "No messages yet.";

        chat.scrollTop =
            chat.scrollHeight;

        let findingsHtml = "";

        for(const finding of data.findings){

            findingsHtml += `
                <div class="card"
                     style="margin:10px 0">

                    <h3>
                        ${escapeHtml(finding.title)}
                    </h3>

                    <div class="badge">
                        ${escapeHtml(finding.severity)}
                    </div>

                    <p>
                        ${escapeHtml(finding.description)}
                    </p>

                    <p>
                        <b>Evidence:</b>
                    </p>

                    <pre style="white-space:pre-wrap">
${escapeHtml(finding.evidence)}
                    </pre>

                    <p>
                        <b>Recommendation:</b>
                    </p>

                    <p>
                        ${escapeHtml(
                            finding.recommendation
                        )}
                    </p>

                </div>
            `;
        }

        document.getElementById("findings")
            .innerHTML =
                findingsHtml ||
                "No findings.";

        firstLoad = false;

    }catch(error){

        console.error(error);

    }
}


async function setStatus(status){

    try{

        const response =
            await fetch(
                `/staff/client/${requestId}/status`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify({
                        status:status
                    })
                }
            );

        if(response.ok){

            await loadClient();

            showToast(
                "STATUS UPDATED",
                status
            );
        }

    }catch(error){

        console.error(error);

    }
}


async function sendMessage(){

    const input =
        document.getElementById("message");

    const message =
        input.value.trim();

    if(!message){
        return;
    }

    input.value = "";

    try{

        const response =
            await fetch(
                `/staff/client/${requestId}/message`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify({
                        message:message
                    })
                }
            );

        if(response.ok){
            await loadClient();
        }

    }catch(error){

        console.error(error);
    }
}


async function addFinding(event){

    event.preventDefault();

    const payload = {
        title:
            document.getElementById(
                "finding_title"
            ).value,

        severity:
            document.getElementById(
                "finding_severity"
            ).value,

        description:
            document.getElementById(
                "finding_description"
            ).value,

        evidence:
            document.getElementById(
                "finding_evidence"
            ).value,

        recommendation:
            document.getElementById(
                "finding_recommendation"
            ).value
    };

    try{

        const response =
            await fetch(
                `/staff/client/${requestId}/finding`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify(payload)
                }
            );

        if(response.ok){

            document
                .querySelector(
                    "form"
                )
                .reset();

            await loadClient();

            showToast(
                "FINDING ADDED",
                "Security finding created."
            );
        }

    }catch(error){

        console.error(error);

    }
}


document
    .getElementById("message")
    .addEventListener(
        "keydown",
        function(event){

            if(event.key === "Enter"){
                sendMessage();
            }

        }
    );


loadClient();

setInterval(
    loadClient,
    1000
);

</script>

</body>
</html>
"""


@app.get("/admin/client/<int:request_id>")
@staff_required
def staff_client(request_id):

    item = get_request(request_id)

    if not item:
        abort(404)

    return render_template_string(
        STAFF_DETAIL,
        item=item,
        dashboard_url="/owner" if is_owner() else "/admin",
    )


# ============================================================
# STAFF CLIENT DATA
# ============================================================

@app.get("/api/staff/client/<int:request_id>/data")
@staff_required
def staff_client_data(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify(
            {
                "error": "not_found"
            }
        ), 404

    messages = query_all(
        """
        SELECT id, sender, message, created_at
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    findings = query_all(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    return jsonify(
        {
            "request": dict(item),
            "messages": [dict(x) for x in messages],
            "findings": [dict(x) for x in findings],
        }
    )


# ============================================================
# STAFF STATUS
# ============================================================

@app.post("/staff/client/<int:request_id>/status")
@staff_required
def staff_status(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify(
            {
                "error": "not_found"
            }
        ), 404

    data = request.get_json(silent=True) or {}

    status = clean_text(
        data.get("status"),
        50,
    )

    if status not in STATUSES:
        return jsonify(
            {
                "error": "invalid_status"
            }
        ), 400

    execute(
        """
        UPDATE requests
        SET status = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            status,
            now(),
            request_id,
        ),
    )

    system_message(
        request_id,
        f"Request status changed to {status}.",
    )

    notify(
        "client",
        "status_change",
        "REQUEST STATUS UPDATED",
        f"Your request is now {status}.",
        request_id,
    )

    audit_action(
        session.get("email", "STAFF"),
        "status_change",
        f"request_id={request_id}; status={status}",
    )

    return jsonify(
        {
            "ok": True,
            "status": status,
        }
    )


# ============================================================
# STAFF MESSAGE
# ============================================================

@app.post("/staff/client/<int:request_id>/message")
@staff_required
def staff_message(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify(
            {
                "error": "not_found"
            }
        ), 404

    data = request.get_json(silent=True) or {}

    message = clean_text(
        data.get("message"),
        4000,
    )

    if not message:
        return jsonify(
            {
                "error": "message_required"
            }
        ), 400

    execute(
        """
        INSERT INTO messages
        (request_id, sender, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            "STAFF",
            message,
            now(),
        ),
    )

    notify(
        "client",
        "staff_message",
        "NEW STAFF MESSAGE",
        message[:300],
        request_id,
    )

    audit_action(
        session.get("email", "STAFF"),
        "staff_message",
        f"request_id={request_id}",
    )

    return jsonify(
        {
            "ok": True
        }
    )


# ============================================================
# FINDING
# ============================================================

@app.post("/staff/client/<int:request_id>/finding")
@staff_required
def staff_finding(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify(
            {
                "error": "not_found"
            }
        ), 404

    data = request.get_json(silent=True) or {}

    title = clean_text(
        data.get("title"),
        300,
    )

    severity = clean_text(
        data.get("severity"),
        30,
    )

    description = clean_text(
        data.get("description"),
        5000,
    )

    evidence = clean_text(
        data.get("evidence"),
        8000,
    )

    recommendation = clean_text(
        data.get("recommendation"),
        5000,
    )

    if not title:
        return jsonify(
            {
                "error": "title_required"
            }
        ), 400

    if severity not in SEVERITIES:
        return jsonify(
            {
                "error": "invalid_severity"
            }
        ), 400

    if not description:
        return jsonify(
            {
                "error": "description_required"
            }
        ), 400

    finding_id = execute(
        """
        INSERT INTO findings
        (
            request_id,
            title,
            severity,
            description,
            evidence,
            recommendation,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            title,
            severity,
            description,
            evidence,
            recommendation,
            now(),
        ),
    )

    notify(
        "client",
        "finding",
        "NEW SECURITY FINDING",
        title,
        request_id,
    )

    audit_action(
        session.get("email", "STAFF"),
        "finding_created",
        f"request_id={request_id}; finding_id={finding_id}",
    )

    return jsonify(
        {
            "ok": True,
            "finding_id": finding_id,
        }
    )


# ============================================================
# STAFF REPORT
# ============================================================

@app.get("/staff/client/<int:request_id>/report")
@staff_required
def staff_report(request_id):

    item = get_request(request_id)

    if not item:
        abort(404)

    findings = query_all(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    )

    return render_template_string(
        REPORT_PAGE,
        item=item,
        findings=findings,
    )


# ============================================================
# STAFF NOTIFICATIONS
# ============================================================

@app.get("/api/staff/notifications")
@staff_required
def staff_notifications():

    after = safe_int(
        request.args.get("after"),
        0,
    )

    rows = query_all(
        """
        SELECT
            id,
            request_id,
            kind,
            title,
            body,
            created_at
        FROM notifications
        WHERE audience = 'staff'
        AND id > ?
        ORDER BY id ASC
        LIMIT 100
        """,
        (after,),
    )

    return jsonify(
        {
            "notifications": [
                dict(row)
                for row in rows
            ]
        }
    )


# ============================================================
# COMMAND ENGINE
# ============================================================

MAINTENANCE_KEY = "maintenance"


def get_setting(key, default=""):
    row = query_one(
        """
        SELECT value
        FROM settings
        WHERE key = ?
        """,
        (key,),
    )

    if not row:
        return default

    return row["value"]


def set_setting(key, value):
    execute(
        """
        INSERT INTO settings(key,value)
        VALUES (?,?)
        ON CONFLICT(key)
        DO UPDATE SET value=excluded.value
        """,
        (
            key,
            value,
        ),
    )


def command_help(owner=False):

    lines = [
        "MATIA // SECURITY CHECK TERMINAL",
        "",
        "CORE:",
        "  help",
        "  menu",
        "  clear",
        "  version",
        "  time",
        "  uptime",
        "  health",
        "  system",
        "",
        "REQUESTS:",
        "  clients",
        "  list",
        "  all",
        "  pending",
        "  accepted",
        "  active",
        "  completed",
        "  declined",
        "  stats",
        "  client <id>",
        "  status <id>",
        "  request <id>",
        "",
        "ACTIONS:",
        "  accept <id>",
        "  decline <id>",
        "  start <id>",
        "  complete <id>",
        "  reopen <id>",
        "  message <id> <text>",
        "  msg <id> <text>",
        "",
        "SECURITY:",
        "  findings <id>",
        "  findings-total",
        "  report <id>",
        "  search <term>",
        "",
        "COMMUNICATION:",
        "  announce <text>",
        "  broadcast <text>",
        "  notify <id> <text>",
        "",
    ]

    if owner:

        lines.extend(
            [
                "OWNER:",
                "  audit",
                "  logs",
                "  users",
                "  admins",
                "  maintenance",
                "  maintenance on",
                "  maintenance off",
                "  maintenance status",
                "  db",
                "  database",
                "  settings",
                "  ring",
                "  info",
                "",
                "Aliases are supported for many commands.",
                "This terminal controls the application data",
                "and does not execute arbitrary OS shell commands.",
            ]
        )

    else:

        lines.extend(
            [
                "ADMIN:",
                "  audit",
                "  logs",
                "  ring",
                "",
            ]
        )

    return "\n".join(lines)


def command_list(status_filter=None):

    if status_filter:

        rows = query_all(
            """
            SELECT id,name,email,target,status
            FROM requests
            WHERE status = ?
            ORDER BY id DESC
            """,
            (status_filter,),
        )

    else:

        rows = query_all(
            """
            SELECT id,name,email,target,status
            FROM requests
            ORDER BY id DESC
            """
        )

    if not rows:
        return "No requests found."

    lines = []

    for row in rows:

        lines.append(
            f"#{row['id']} | "
            f"{row['status']:<12} | "
            f"{row['name']} | "
            f"{row['target']}"
        )

    return "\n".join(lines)


def command_client(request_id):

    item = get_request(request_id)

    if not item:
        return "Client/request not found."

    return "\n".join(
        [
            f"ID: #{item['id']}",
            f"Name: {item['name']}",
            f"Email: {item['email']}",
            f"Project: {item['web_name']}",
            f"Target: {item['target']}",
            f"Status: {item['status']}",
            f"Created: {item['created_at']}",
            f"Updated: {item['updated_at']}",
            "",
            "AUTHORIZED SCOPE:",
            item["scope"],
        ]
    )


def command_findings(request_id):

    rows = query_all(
        """
        SELECT id,title,severity
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,),
    )

    if not rows:
        return "No findings."

    lines = []

    for row in rows:

        lines.append(
            f"F-{row['id']} | "
            f"{row['severity']} | "
            f"{row['title']}"
        )

    return "\n".join(lines)


def change_status_command(request_id, status):

    item = get_request(request_id)

    if not item:
        return "Client/request not found."

    execute(
        """
        UPDATE requests
        SET status = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            status,
            now(),
            request_id,
        ),
    )

    system_message(
        request_id,
        f"Request status changed to {status}.",
    )

    notify(
        "client",
        "status_change",
        "REQUEST STATUS UPDATED",
        f"Your request is now {status}.",
        request_id,
    )

    return (
        f"Request #{request_id} "
        f"status changed to {status}."
    )


def execute_command(command, owner=False):

    command = clean_text(
        command,
        5000,
    )

    if not command:
        return ""

    audit_action(
        session.get("email", "STAFF"),
        "terminal_command",
        command[:1000],
    )

    parts = command.split()

    cmd = parts[0].lower()

    args = parts[1:]

    aliases = {
        "?": "help",
        "commands": "help",
        "ls": "clients",
        "list": "clients",
        "all": "clients",
        "req": "request",
        "requests": "clients",
        "active": "inprogress",
        "in-progress": "inprogress",
        "in_progress": "inprogress",
        "find": "search",
        "msg": "message",
        "send": "message",
        "broadcast": "announce",
        "dbinfo": "db",
        "db-status": "db",
        "logs": "audit",
    }

    cmd = aliases.get(cmd, cmd)

    if cmd == "help":
        return command_help(owner)

    if cmd == "menu":
        return command_help(owner)

    if cmd == "clear":
        return "__CLEAR__"

    if cmd == "version":
        return (
            f"{APP_NAME}\n"
            f"Version: {APP_VERSION}\n"
            f"Python Flask application"
        )

    if cmd == "time":
        return now()

    if cmd == "uptime":

        seconds = uptime_seconds()

        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60

        return (
            f"Uptime: "
            f"{hours}h "
            f"{minutes}m "
            f"{secs}s"
        )

    if cmd == "health":

        try:
            row = query_one(
                "SELECT 1 AS ok"
            )

            database = (
                "ONLINE"
                if row and row["ok"] == 1
                else "ERROR"
            )

        except Exception:
            database = "ERROR"

        return (
            "APPLICATION: ONLINE\n"
            f"DATABASE: {database}\n"
            f"VERSION: {APP_VERSION}\n"
            f"ROLE: {role()}"
        )

    if cmd in ("system", "info"):

        return (
            f"APPLICATION: {APP_NAME}\n"
            f"VERSION: {APP_VERSION}\n"
            f"ROLE: {role()}\n"
            f"TIME: {now()}\n"
            f"UPTIME: {uptime_seconds()} seconds"
        )

    if cmd in ("clients",):

        return command_list()

    if cmd == "pending":

        return command_list("PENDING")

    if cmd == "accepted":

        return command_list("ACCEPTED")

    if cmd == "inprogress":

        return command_list("IN PROGRESS")

    if cmd == "completed":

        return command_list("COMPLETED")

    if cmd == "declined":

        return command_list("DECLINED")

    if cmd == "stats":

        s = stats()

        return "\n".join(
            [
                f"TOTAL       : {s['TOTAL']}",
                f"PENDING     : {s['PENDING']}",
                f"ACCEPTED    : {s['ACCEPTED']}",
                f"IN PROGRESS : {s['IN PROGRESS']}",
                f"COMPLETED   : {s['COMPLETED']}",
                f"DECLINED    : {s['DECLINED']}",
            ]
        )

    if cmd in ("client", "request"):

        if not args:
            return "Usage: client <id>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        return command_client(request_id)

    if cmd == "status":

        if not args:
            return "Usage: status <id>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        item = get_request(request_id)

        if not item:
            return "Request not found."

        return (
            f"#{request_id}: "
            f"{item['status']}"
        )

    status_commands = {
        "accept": "ACCEPTED",
        "decline": "DECLINED",
        "start": "IN PROGRESS",
        "complete": "COMPLETED",
        "reopen": "PENDING",
    }

    if cmd in status_commands:

        if not args:
            return f"Usage: {cmd} <id>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        return change_status_command(
            request_id,
            status_commands[cmd],
        )

    if cmd == "message":

        if len(args) < 2:
            return "Usage: message <id> <text>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        message = " ".join(args[1:])

        item = get_request(request_id)

        if not item:
            return "Request not found."

        execute(
            """
            INSERT INTO messages
            (request_id,sender,message,created_at)
            VALUES (?,?,?,?)
            """,
            (
                request_id,
                "STAFF",
                message,
                now(),
            ),
        )

        notify(
            "client",
            "staff_message",
            "NEW STAFF MESSAGE",
            message[:300],
            request_id,
        )

        return (
            f"Message sent to request #{request_id}."
        )

    if cmd == "findings":

        if not args:
            return "Usage: findings <id>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        return command_findings(request_id)

    if cmd == "findings-total":

        row = query_one(
            """
            SELECT COUNT(*) AS total
            FROM findings
            """
        )

        return (
            f"Total findings: "
            f"{row['total']}"
        )

    if cmd == "report":

        if not args:
            return "Usage: report <id>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        item = get_request(request_id)

        if not item:
            return "Request not found."

        findings_count = query_one(
            """
            SELECT COUNT(*) AS total
            FROM findings
            WHERE request_id = ?
            """,
            (request_id,),
        )["total"]

        return (
            f"REPORT #{request_id}\n"
            f"Target: {item['target']}\n"
            f"Status: {item['status']}\n"
            f"Findings: {findings_count}\n"
            f"URL: /report/{request_id}"
        )

    if cmd == "search":

        if not args:
            return "Usage: search <term>"

        term = "%" + " ".join(args) + "%"

        rows = query_all(
            """
            SELECT id,name,email,web_name,target,status
            FROM requests
            WHERE name LIKE ?
               OR email LIKE ?
               OR web_name LIKE ?
               OR target LIKE ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (
                term,
                term,
                term,
                term,
            ),
        )

        if not rows:
            return "No matches."

        return "\n".join(
            [
                (
                    f"#{r['id']} | "
                    f"{r['name']} | "
                    f"{r['target']} | "
                    f"{r['status']}"
                )
                for r in rows
            ]
        )

    if cmd in ("announce", "broadcast"):

        if not args:
            return "Usage: announce <text>"

        message = " ".join(args)

        notify(
            "client",
            "announcement",
            "MATIA SECURITY ANNOUNCEMENT",
            message[:1000],
            None,
        )

        return "Announcement sent."

    if cmd == "notify":

        if len(args) < 2:
            return "Usage: notify <id> <text>"

        request_id = safe_int(args[0])

        if request_id is None:
            return "Invalid request ID."

        item = get_request(request_id)

        if not item:
            return "Request not found."

        message = " ".join(args[1:])

        notify(
            "client",
            "manual",
            "MATIA // NOTIFICATION",
            message,
            request_id,
        )

        return (
            f"Notification sent to #{request_id}."
        )

    if cmd == "audit":

        rows = query_all(
            """
            SELECT actor,action,details,created_at
            FROM audit_log
            ORDER BY id DESC
            LIMIT 50
            """
        )

        if not rows:
            return "No audit entries."

        return "\n".join(
            [
                (
                    f"{r['created_at']} | "
                    f"{r['actor']} | "
                    f"{r['action']} | "
                    f"{r['details'] or ''}"
                )
                for r in rows
            ]
        )

    if cmd == "users":

        if not owner:
            return "OWNER ONLY."

        return (
            "Application staff accounts are configured "
            "through environment variables.\n"
            "No credentials are displayed by the terminal."
        )

    if cmd == "admins":

        if not owner:
            return "OWNER ONLY."

        return (
            "Admin authentication is configured "
            "through MATIA_ADMIN_EMAIL and "
            "MATIA_ADMIN_PASSWORD."
        )

    if cmd == "maintenance":

        if not owner:
            return "OWNER ONLY."

        if not args:

            state = get_setting(
                MAINTENANCE_KEY,
                "off",
            )

            return (
                f"Maintenance: {state}"
            )

        action = args[0].lower()

        if action == "status":

            state = get_setting(
                MAINTENANCE_KEY,
                "off",
            )

            return (
                f"Maintenance: {state}"
            )

        if action == "on":

            set_setting(
                MAINTENANCE_KEY,
                "on",
            )

            return "Maintenance enabled."

        if action == "off":

            set_setting(
                MAINTENANCE_KEY,
                "off",
            )

            return "Maintenance disabled."

        return (
            "Usage: maintenance "
            "[on|off|status]"
        )

    if cmd in ("db", "database"):

        try:

            row = query_one(
                "SELECT COUNT(*) AS total FROM requests"
            )

            messages = query_one(
                "SELECT COUNT(*) AS total FROM messages"
            )

            findings = query_one(
                "SELECT COUNT(*) AS total FROM findings"
            )

            return (
                "DATABASE: ONLINE\n"
                f"Requests: {row['total']}\n"
                f"Messages: {messages['total']}\n"
                f"Findings: {findings['total']}"
            )

        except Exception as exc:

            return (
                f"DATABASE ERROR: {exc}"
            )

    if cmd == "settings":

        if not owner:
            return "OWNER ONLY."

        maintenance = get_setting(
            MAINTENANCE_KEY,
            "off",
        )

        return (
            f"maintenance={maintenance}"
        )

    if cmd == "ring":

        return (
            "Ring is controlled by each "
            "browser session.\n"
            "Use ENABLE RING in the dashboard."
        )

    return (
        f"Unknown command: {cmd}\n"
        "Type 'help' for available commands."
    )


# ============================================================
# TERMINAL PAGE
# ============================================================

TERMINAL_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MATIA Terminal</title>
""" + STAFF_STYLE + """
</head>

<body>

<div class="nav">

<div class="logo">
MATIA // {{ role_name|upper }} TERMINAL
</div>

<div class="navlinks">

<a href="{{ dashboard_url }}">
Dashboard
</a>

<button onclick="enableRing()">
🔔 ENABLE RING
</button>

<a href="/logout">
Logout
</a>

</div>

</div>

<div class="container">

<div class="terminal">

<div
id="output"
class="terminal-output"
>
MATIA // SECURITY CHECK
Version {{ version }}

Authenticated:
{{ email }}

Role:
{{ role_name|upper }}

Type 'help' for commands.

--------------------------------------------------
</div>

<div class="terminal-input">

<span style="color:#00ff9c">
root@matia:~$
</span>

<input
id="command"
autocomplete="off"
autofocus
placeholder="type command..."
>

<button
class="btn"
onclick="runCommand()"
>
EXEC
</button>

</div>

</div>

<div class="card" style="margin-top:15px">

<b>OWNER TERMINAL</b>

<p class="muted">
Application-control terminal. It intentionally does
not execute arbitrary operating-system shell commands.
</p>

</div>

</div>

<div id="notification" class="notification"></div>

""" + STAFF_JS + """

<script>

const output =
    document.getElementById("output");

const input =
    document.getElementById("command");


function print(text){

    output.textContent +=
        "\\n" +
        text +
        "\\n";

    output.scrollTop =
        output.scrollHeight;
}


async function runCommand(){

    const command =
        input.value.trim();

    if(!command){
        return;
    }

    print(
        "root@matia:~$ " +
        command
    );

    input.value = "";

    try{

        const response =
            await fetch(
                "{{ command_url }}",
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify({
                        command:command
                    })
                }
            );

        const data =
            await response.json();

        if(data.output === "__CLEAR__"){

            output.textContent = "";

        }else{

            print(
                data.output || ""
            );
        }

    }catch(error){

        print(
            "ERROR: " +
            error
        );
    }
}


input.addEventListener(
    "keydown",
    function(event){

        if(event.key === "Enter"){
            runCommand();
        }

    }
);

</script>

</body>
</html>
"""


@app.get("/owner/terminal")
@role_required("owner")
def owner_terminal():

    return render_template_string(
        TERMINAL_PAGE,
        role_name="owner",
        email=session.get("email", ""),
        version=APP_VERSION,
        dashboard_url="/owner",
        command_url="/owner/command",
    )


@app.get("/admin/terminal")
@role_required("admin")
def admin_terminal():

    return render_template_string(
        TERMINAL_PAGE,
        role_name="admin",
        email=session.get("email", ""),
        version=APP_VERSION,
        dashboard_url="/admin",
        command_url="/admin/command",
    )


# ============================================================
# COMMAND API
# ============================================================

@app.post("/owner/command")
@role_required("owner")
def owner_command():

    data = request.get_json(silent=True) or {}

    command = clean_text(
        data.get("command"),
        5000,
    )

    output = execute_command(
        command,
        owner=True,
    )

    return jsonify(
        {
            "ok": True,
            "output": output,
        }
    )


@app.post("/admin/command")
@role_required("admin")
def admin_command():

    data = request.get_json(silent=True) or {}

    command = clean_text(
        data.get("command"),
        5000,
    )

    output = execute_command(
        command,
        owner=False,
    )

    return jsonify(
        {
            "ok": True,
            "output": output,
        }
    )


# ============================================================
# ADMIN TERMINAL LINK
# ============================================================

@app.get("/admin/tools")
@staff_required
def admin_tools():

    target = (
        "/owner/terminal"
        if is_owner()
        else "/admin/terminal"
    )

    return redirect(target)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    try:

        row = query_one(
            "SELECT 1 AS ok"
        )

        database = (
            row["ok"] == 1
            if row
            else False
        )

    except Exception:

        database = False

    return jsonify(
        {
            "status": "ok" if database else "degraded",
            "app": APP_NAME,
            "version": APP_VERSION,
            "database": database,
            "time": now(),
        }
    )


# ============================================================
# 404
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>404</title>
        <style>
        body{
            background:#020303;
            color:#00ff9c;
            font-family:Consolas,monospace;
            padding:50px;
        }
        a{color:#00ff9c}
        </style>
        </head>
        <body>
        <h1>404 // NODE NOT FOUND</h1>
        <p>The requested route does not exist.</p>
        <a href="/">Return to main system</a>
        </body>
        </html>
        """
    ), 404


# ============================================================
# 500
# ============================================================

@app.errorhandler(500)
def server_error(error):

    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>500</title>
        <style>
        body{
            background:#020303;
            color:#ff7777;
            font-family:Consolas,monospace;
            padding:50px;
        }
        a{color:#00ff9c}
        </style>
        </head>
        <body>
        <h1>500 // INTERNAL ERROR</h1>
        <p>The application encountered an internal error.</p>
        <a href="/">Return to main system</a>
        </body>
        </html>
        """
    ), 500


# ============================================================
# DATABASE INIT
# ============================================================

init_db()


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000",
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )
