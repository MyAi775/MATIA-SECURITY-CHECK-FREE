import os
import re
import hmac
import json
import sqlite3
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
    jsonify,
    abort,
    Response,
)
from markupsafe import escape
from werkzeug.middleware.proxy_fix import ProxyFix

# ============================================================
# MATIA // SECURITY CHECK
# Full Flask Application
# ============================================================

APP_NAME = "MATIA // SECURITY CHECK"
APP_VERSION = "3.1.0"

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
# GOOGLE SEARCH CONSOLE
# ============================================================

@app.route("/googled6013c64975ddc7c.html")
def google_search_console_verification():
    return "google-site-verification: googled6013c64975ddc7c.html"

@app.route("/sitemap.xml")
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://matia-security-check-free.onrender.com/</loc>
    </url>
    <url>
        <loc>https://matia-security-check-free.onrender.com/how-it-works</loc>
    </url>
    <url>
        <loc>https://matia-security-check-free.onrender.com/request</loc>
    </url>
</urlset>"""
    return Response(xml, mimetype="application/xml")

@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://matia-security-check-free.onrender.com/sitemap.xml\n",
        mimetype="text/plain",
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

        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER UNIQUE NOT NULL,
            rating INTEGER NOT NULL,
            message TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT 'Verified Client',
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id)
        );

        CREATE INDEX IF NOT EXISTS idx_feedback_created
        ON feedback(created_at);

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
<div class="card" style="grid-column:1/-1">
    <b>05 // CLIENT FEEDBACK</b>
    <p>Verified clients can leave feedback after a completed assessment.</p>
    {% if feedback %}
        {% for item in feedback %}
        <div style="margin-top:14px;padding:14px;border:1px solid #123a2c;border-radius:10px">
            <div style="color:#00ff9c;letter-spacing:2px">
                {{ "★" * item["rating"] }}{{ "☆" * (5 - item["rating"]) }}
            </div>
            <div style="margin-top:7px">{{ item["message"] }}</div>
            <div style="margin-top:7px;color:#71877e;font-size:13px">
                — {{ item["display_name"] }}
            </div>
        </div>
        {% endfor %}
    {% else %}
        <p style="color:#71877e">No client feedback yet.</p>
    {% endif %}
</div>

</div>

</section>
</body>
</html>
"""


@app.get("/")
def home():
    feedback = query_all(
        """
        SELECT rating, message, display_name, created_at
        FROM feedback
        ORDER BY id DESC
        LIMIT 6
        """
    )

    return render_template_string(
        HOME_PAGE,
        app_name=APP_NAME,
        feedback=feedback,
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
<h2>// CLIENT FEEDBACK</h2>
<div id="feedbackArea">
    <p style="color:#91aaa0">
        Feedback becomes available after the assessment is completed.
    </p>
</div>
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


let selectedRating = 0;

function setRating(value){
    selectedRating = value;
    const buttons = document.querySelectorAll("#stars button");
    buttons.forEach((button,index)=>{
        button.style.color = index < value ? "#00ff9c" : "#4b635a";
    });
}

async function submitFeedback(){
    const message = document.getElementById("feedbackMessage")?.value.trim();
    const displayName = document.getElementById("feedbackName")?.value.trim();

    if(!selectedRating){
        alert("Please select a rating.");
        return;
    }

    if(!message){
        alert("Please write a short feedback message.");
        return;
    }

    try{
        const response = await fetch(
            `/api/client/${requestId}/feedback`,
            {
                method:"POST",
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify({
                    token:token,
                    rating:selectedRating,
                    message:message,
                    display_name:displayName
                })
            }
        );

        const data = await response.json();

        if(!response.ok){
            alert(data.error || "Could not submit feedback.");
            return;
        }

        await loadData();
        alert("Feedback submitted. Thank you!");
    }catch(e){
        console.error(e);
        alert("Could not submit feedback.");
    }
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

        const feedbackArea =
            document.getElementById("feedbackArea");

        const existingFeedback =
            data.feedback;

        if(existingFeedback){
            feedbackArea.innerHTML = `
                <div style="color:#00ff9c;font-size:20px">
                    ${"★".repeat(existingFeedback.rating)}${"☆".repeat(5-existingFeedback.rating)}
                </div>
                <p>${escapeHtml(existingFeedback.message)}</p>
                <div style="color:#71877e">
                    — ${escapeHtml(existingFeedback.display_name)}
                </div>
            `;
        }else if(data.request.status === "COMPLETED"){
            feedbackArea.innerHTML = `
                <div style="margin-bottom:10px;color:#91aaa0">
                    Your assessment is complete. Leave a quick review:
                </div>
                <div id="stars" style="font-size:30px;margin-bottom:10px">
                    <button type="button" onclick="setRating(1)">★</button>
                    <button type="button" onclick="setRating(2)">★</button>
                    <button type="button" onclick="setRating(3)">★</button>
                    <button type="button" onclick="setRating(4)">★</button>
                    <button type="button" onclick="setRating(5)">★</button>
                </div>
                <input id="feedbackName" maxlength="80" placeholder="Display name (optional)" style="width:100%;padding:12px;background:#020303;color:#d8fff0;border:1px solid #173d30;border-radius:8px">
                <textarea id="feedbackMessage" maxlength="1000" placeholder="Tell us about your experience..." style="width:100%;min-height:100px;margin-top:10px;padding:12px;background:#020303;color:#d8fff0;border:1px solid #173d30;border-radius:8px"></textarea>
                <button onclick="submitFeedback()" style="margin-top:10px;padding:11px 16px;background:#00ff9c;color:#001b11;border:0;border-radius:8px;font-weight:800">SUBMIT FEEDBACK</button>
            `;
        }

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
            "feedback": (
                dict(query_one(
                    """
                    SELECT rating, message, display_name, created_at
                    FROM feedback
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ))
                if query_one(
                    "SELECT 1 AS ok FROM feedback WHERE request_id = ?",
                    (request_id,),
                )
                else None
            ),
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


@app.post("/api/client/<int:request_id>/feedback")
def client_feedback(request_id):
    data = request.get_json(silent=True) or {}

    token = clean_text(data.get("token"), 300)
    message = clean_text(data.get("message"), 1000)
    display_name = clean_text(
        data.get("display_name") or "Verified Client",
        80,
    )
    rating = safe_int(data.get("rating"))

    item = get_request_by_token(
        request_id,
        token,
    )

    if not item:
        return jsonify({"error": "access_denied"}), 403

    if item["status"] != "COMPLETED":
        return jsonify(
            {"error": "feedback_available_after_completion"}
        ), 400

    if rating is None or rating < 1 or rating > 5:
        return jsonify({"error": "rating_must_be_1_to_5"}), 400

    if not message:
        return jsonify({"error": "message_required"}), 400

    existing = query_one(
        "SELECT id FROM feedback WHERE request_id = ?",
        (request_id,),
    )

    if existing:
        return jsonify({"error": "feedback_already_submitted"}), 409

    execute(
        """
        INSERT INTO feedback
        (request_id, rating, message, display_name, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            request_id,
            rating,
            message,
            display_name,
            now(),
        ),
    )

    audit_action(
        "CLIENT",
        "SUBMIT_FEEDBACK",
        f"request_id={request_id}; rating={rating}",
    )

    notify(
        "staff",
        "client_feedback",
        "NEW CLIENT FEEDBACK",
        f"Request #{request_id} submitted a {rating}/5 review.",
        request_id,
    )

    return jsonify({"ok": True})


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