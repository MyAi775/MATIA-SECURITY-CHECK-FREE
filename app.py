import os
import html
import secrets
import socket
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    request,
    redirect,
    session,
    url_for,
    abort,
)
from flask_socketio import SocketIO, join_room

# ============================================================
# MATIA // SECURITY CHECK
# Authorized Security Assessment Portal
# ============================================================

APP_NAME = "MATIA // SECURITY CHECK"

ADMIN_EMAIL = os.getenv(
    "MATIA_ADMIN_EMAIL",
    "kleimatia1@gmail.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv("MATIA_ADMIN_PASSWORD")
SECRET_KEY = os.getenv("MATIA_SECRET_KEY")

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "MATIA_ADMIN_PASSWORD is missing. Add it in Render Environment Variables."
    )

if not SECRET_KEY:
    raise RuntimeError(
        "MATIA_SECRET_KEY is missing. Add it in Render Environment Variables."
    )

DB_FILE = os.getenv("MATIA_DB_FILE", "matia_security.db")
PORT = int(os.getenv("PORT", "5000"))

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "COOKIE_SECURE", "true"
).lower() == "true"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# ============================================================
# DATABASE
# ============================================================

def db():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_column(connection, table, column, definition):
    existing = {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    if column not in existing:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    connection = db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_token TEXT UNIQUE,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            web_name TEXT NOT NULL,
            target TEXT NOT NULL,
            scope TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            client_ip TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES requests(id)
        )
    """)

    connection.execute("""
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
        )
    """)

    # Migration support for older database versions
    ensure_column(
        connection,
        "requests",
        "client_token",
        "TEXT"
    )

    ensure_column(
        connection,
        "requests",
        "web_name",
        "TEXT"
    )

    connection.commit()

    # Repair old rows where necessary
    rows = connection.execute(
        """
        SELECT id, client_token, web_name
        FROM requests
        """
    ).fetchall()

    for row in rows:
        changed = False
        token = row["client_token"]
        web_name = row["web_name"]

        if not token:
            token = secrets.token_urlsafe(32)
            changed = True

        if not web_name:
            web_name = "Unnamed Website"
            changed = True

        if changed:
            connection.execute(
                """
                UPDATE requests
                SET client_token = ?, web_name = ?
                WHERE id = ?
                """,
                (token, web_name, row["id"])
            )

    connection.commit()
    connection.close()


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def esc(value):
    return html.escape(str(value or ""), quote=True)


def valid_target(target):
    try:
        parsed = urlparse(target.strip())

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.netloc:
            return False

        return True
    except Exception:
        return False


def resolve_target(target):
    try:
        hostname = urlparse(target).hostname

        if not hostname:
            return None

        return socket.gethostbyname(hostname)
    except Exception:
        return None


def get_request(request_id):
    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,)
    ).fetchone()

    connection.close()
    return row


def client_authorized(request_id, token):
    if not token:
        return False

    connection = db()

    row = connection.execute(
        """
        SELECT id
        FROM requests
        WHERE id = ?
          AND client_token = ?
        """,
        (request_id, token)
    ).fetchone()

    connection.close()

    return row is not None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))

        return fn(*args, **kwargs)

    return wrapper


def severity_class(severity):
    severity = (severity or "").upper()

    if severity == "CRITICAL":
        return "critical"

    if severity == "HIGH":
        return "high"

    if severity == "MEDIUM":
        return "medium"

    if severity == "LOW":
        return "low"

    return "info"


# ============================================================
# SHARED UI
# ============================================================

BASE_CSS = r"""
:root{
    --bg:#06070b;
    --panel:#0d1118;
    --panel2:#111722;
    --border:#1d2735;
    --text:#eef4ff;
    --muted:#91a0b5;
    --accent:#6d7cff;
    --accent2:#00e5ff;
    --green:#23e68a;
    --yellow:#ffc857;
    --orange:#ff8a3d;
    --red:#ff4d67;
    --shadow:0 20px 60px rgba(0,0,0,.35);
}

*{
    box-sizing:border-box;
}

html{
    scroll-behavior:smooth;
}

body{
    margin:0;
    background:
        radial-gradient(circle at 15% 10%, rgba(109,124,255,.12), transparent 30%),
        radial-gradient(circle at 85% 20%, rgba(0,229,255,.08), transparent 30%),
        linear-gradient(180deg,#05060a,#080b11 55%,#05070b);
    color:var(--text);
    font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    min-height:100vh;
}

a{
    color:inherit;
    text-decoration:none;
}

.container{
    width:min(1180px,92%);
    margin:auto;
}

.topbar{
    position:sticky;
    top:0;
    z-index:50;
    backdrop-filter:blur(18px);
    background:rgba(5,7,11,.75);
    border-bottom:1px solid rgba(255,255,255,.06);
}

.nav{
    height:72px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:20px;
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
    font-weight:900;
    letter-spacing:.8px;
}

.brand-mark{
    width:38px;
    height:38px;
    display:grid;
    place-items:center;
    border-radius:12px;
    background:linear-gradient(135deg,var(--accent),var(--accent2));
    color:#05070b;
    box-shadow:0 0 30px rgba(109,124,255,.35);
}

.brand small{
    display:block;
    font-size:10px;
    color:var(--muted);
    letter-spacing:1.8px;
    margin-top:2px;
}

.navlinks{
    display:flex;
    align-items:center;
    gap:8px;
}

.navlinks a{
    padding:10px 12px;
    border-radius:10px;
    color:var(--muted);
    transition:.2s;
}

.navlinks a:hover{
    color:var(--text);
    background:rgba(255,255,255,.05);
}

.hero{
    padding:90px 0 45px;
}

.hero-grid{
    display:grid;
    grid-template-columns:1.2fr .8fr;
    gap:25px;
}

.hero h1{
    font-size:clamp(42px,7vw,82px);
    line-height:.95;
    margin:0 0 22px;
    letter-spacing:-4px;
}

.gradient-text{
    background:linear-gradient(90deg,#fff,var(--accent2),#8d96ff);
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent;
}

.hero p{
    color:var(--muted);
    line-height:1.8;
    max-width:720px;
    font-size:17px;
}

.panel{
    background:
        linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015)),
        var(--panel);
    border:1px solid var(--border);
    border-radius:22px;
    box-shadow:var(--shadow);
}

.hero-card{
    padding:25px;
    position:relative;
    overflow:hidden;
}

.hero-card::before{
    content:"";
    position:absolute;
    width:220px;
    height:220px;
    right:-100px;
    top:-100px;
    background:radial-gradient(circle,rgba(0,229,255,.22),transparent 70%);
}

.status-line{
    display:flex;
    align-items:center;
    gap:10px;
    color:var(--green);
    font-weight:700;
    margin-bottom:20px;
}

.dot{
    width:9px;
    height:9px;
    border-radius:50%;
    background:var(--green);
    box-shadow:0 0 15px var(--green);
}

.stats-grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:12px;
    margin-top:25px;
}

.stat{
    padding:18px;
    border:1px solid var(--border);
    background:rgba(255,255,255,.025);
    border-radius:15px;
}

.stat strong{
    display:block;
    font-size:24px;
    margin-bottom:5px;
}

.stat span{
    color:var(--muted);
    font-size:12px;
}

.section{
    padding:35px 0;
}

.section-title{
    font-size:28px;
    margin:0 0 10px;
}

.section-sub{
    color:var(--muted);
    margin:0 0 22px;
}

.form-wrap{
    width:min(850px,100%);
    margin:35px auto 70px;
}

.form-panel{
    padding:30px;
}

.form-grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:18px;
}

.field{
    display:flex;
    flex-direction:column;
    gap:8px;
}

.field.full{
    grid-column:1/-1;
}

label{
    font-size:13px;
    color:#c7d1e1;
    font-weight:700;
}

input,textarea,select{
    width:100%;
    border:1px solid var(--border);
    background:#080b11;
    color:var(--text);
    border-radius:13px;
    padding:14px 15px;
    outline:none;
    transition:.2s;
    font:inherit;
}

input:focus,textarea:focus,select:focus{
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(109,124,255,.13);
}

textarea{
    min-height:130px;
    resize:vertical;
}

.checkbox{
    display:flex;
    align-items:flex-start;
    gap:10px;
    color:var(--muted);
    font-size:13px;
    line-height:1.6;
}

.checkbox input{
    width:auto;
    margin-top:3px;
}

.btn{
    border:0;
    cursor:pointer;
    border-radius:13px;
    padding:13px 17px;
    color:white;
    font-weight:800;
    transition:.2s;
    display:inline-flex;
    justify-content:center;
    align-items:center;
    gap:8px;
}

.btn-primary{
    background:linear-gradient(135deg,var(--accent),#8e62ff);
    box-shadow:0 12px 30px rgba(109,124,255,.2);
}

.btn-primary:hover{
    transform:translateY(-1px);
    box-shadow:0 16px 38px rgba(109,124,255,.28);
}

.btn-dark{
    background:#111722;
    border:1px solid var(--border);
}

.btn-green{
    background:linear-gradient(135deg,#1bc77b,#0ea85f);
}

.btn-red{
    background:linear-gradient(135deg,#ff4d67,#e83e57);
}

.notice{
    padding:14px 16px;
    border-radius:13px;
    margin-bottom:18px;
    border:1px solid var(--border);
}

.notice.error{
    background:rgba(255,77,103,.09);
    border-color:rgba(255,77,103,.25);
    color:#ffb8c3;
}

.notice.success{
    background:rgba(35,230,138,.08);
    border-color:rgba(35,230,138,.25);
    color:#9effd1;
}

.cards{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:16px;
}

.card{
    padding:20px;
}

.card h3{
    margin:0 0 8px;
}

.muted{
    color:var(--muted);
}

.table-wrap{
    overflow:auto;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    padding:14px;
    text-align:left;
    border-bottom:1px solid var(--border);
    white-space:nowrap;
}

th{
    color:#9baac0;
    font-size:12px;
    text-transform:uppercase;
    letter-spacing:.7px;
}

td{
    color:#e7edf7;
    font-size:14px;
}

.badge{
    display:inline-flex;
    align-items:center;
    gap:7px;
    padding:6px 10px;
    border-radius:999px;
    font-size:11px;
    font-weight:900;
    letter-spacing:.6px;
    border:1px solid transparent;
}

.badge.pending{
    background:rgba(255,200,87,.09);
    color:#ffd97f;
    border-color:rgba(255,200,87,.22);
}

.badge.accepted,
.badge.completed{
    background:rgba(35,230,138,.09);
    color:#7df5b4;
    border-color:rgba(35,230,138,.22);
}

.badge.progress{
    background:rgba(0,229,255,.09);
    color:#81f2ff;
    border-color:rgba(0,229,255,.22);
}

.badge.declined{
    background:rgba(255,77,103,.09);
    color:#ff9ead;
    border-color:rgba(255,77,103,.22);
}

.severity{
    font-weight:900;
}

.severity.critical{
    color:#ff6076;
}

.severity.high{
    color:#ff8e65;
}

.severity.medium{
    color:#ffd26a;
}

.severity.low{
    color:#65e9a8;
}

.severity.info{
    color:#79dfff;
}

.dashboard-grid{
    display:grid;
    grid-template-columns:1.2fr .8fr;
    gap:18px;
}

.kpi-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:12px;
}

.kpi{
    padding:20px;
}

.kpi strong{
    font-size:28px;
    display:block;
}

.kpi span{
    font-size:12px;
    color:var(--muted);
}

.chat{
    display:flex;
    flex-direction:column;
    min-height:520px;
}

.chat-box{
    flex:1;
    overflow:auto;
    padding:20px;
    display:flex;
    flex-direction:column;
    gap:12px;
    max-height:520px;
}

.msg{
    max-width:80%;
    padding:11px 13px;
    border-radius:15px;
    border:1px solid var(--border);
    background:#0a0f16;
}

.msg.admin{
    align-self:flex-end;
    background:rgba(109,124,255,.12);
    border-color:rgba(109,124,255,.2);
}

.msg.client{
    align-self:flex-start;
}

.msg .who{
    font-size:10px;
    font-weight:900;
    color:var(--muted);
    text-transform:uppercase;
    letter-spacing:.8px;
    margin-bottom:5px;
}

.msg .time{
    margin-top:6px;
    color:#66748a;
    font-size:10px;
}

.chat-form{
    display:flex;
    gap:10px;
    padding:15px;
    border-top:1px solid var(--border);
}

.chat-form input{
    flex:1;
}

.finding{
    padding:22px;
    margin-bottom:14px;
}

.finding-header{
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    gap:15px;
}

.finding h3{
    margin:0 0 8px;
}

.report-head{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:15px;
    margin-bottom:22px;
}

.code-box{
    background:#05070a;
    border:1px solid var(--border);
    border-radius:13px;
    padding:14px;
    overflow:auto;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size:12px;
    color:#b8c6da;
}

.footer{
    padding:55px 0;
    color:#66748a;
    text-align:center;
    font-size:12px;
}

.login{
    width:min(480px,92%);
    margin:90px auto;
}

.login-panel{
    padding:30px;
}

.empty{
    padding:35px;
    text-align:center;
    color:var(--muted);
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:9px;
}

@media(max-width:900px){
    .hero-grid,
    .dashboard-grid{
        grid-template-columns:1fr;
    }

    .cards{
        grid-template-columns:1fr;
    }

    .kpi-grid{
        grid-template-columns:repeat(2,1fr);
    }

    .hero h1{
        letter-spacing:-2px;
    }
}

@media(max-width:650px){
    .navlinks{
        display:none;
    }

    .form-grid{
        grid-template-columns:1fr;
    }

    .field.full{
        grid-column:auto;
    }

    .kpi-grid{
        grid-template-columns:1fr 1fr;
    }

    .hero{
        padding-top:55px;
    }

    .stats-grid{
        grid-template-columns:1fr;
    }
}
"""


def page(title, body, script=""):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {APP_NAME}</title>
<style>
{BASE_CSS}
</style>
<script src="https://cdn.socket.io/4.8.1/socket.io.min.js"></script>
</head>
<body>

<div class="topbar">
    <div class="container nav">
        <a class="brand" href="{url_for('home')}">
            <div class="brand-mark">M</div>
            <div>
                MATIA // SECURITY
                <small>AUTHORIZED SECURITY CHECKS</small>
            </div>
        </a>

        <div class="navlinks">
            <a href="{url_for('home')}">Home</a>
            <a href="{url_for('new_request')}">Request</a>
            <a href="{url_for('admin_login')}">Admin</a>
        </div>
    </div>
</div>

<main>
{body}
</main>

<div class="footer">
    MATIA // SECURITY CHECK · Authorized Security Assessment Portal
</div>

<script>
{script}
</script>

</body>
</html>"""


# ============================================================
# SOCKET.IO
# ============================================================

@socketio.on("join_request")
def join_request(data):
    try:
        request_id = int(data.get("request_id"))
    except Exception:
        return

    join_room(f"request_{request_id}")


@socketio.on("join_admin")
def join_admin():
    if session.get("admin_logged_in"):
        join_room("admin")


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    body = """
    <section class="hero">
        <div class="container hero-grid">

            <div>
                <div class="status-line">
                    <span class="dot"></span>
                    SECURITY PORTAL ONLINE
                </div>

                <h1>
                    Find the weak points
                    <span class="gradient-text">
                        before attackers do.
                    </span>
                </h1>

                <p>
                    MATIA // SECURITY CHECK is an authorized security
                    assessment portal for website owners and authorized
                    testers. Submit your website, define the scope, and
                    communicate directly through the secure assessment portal.
                </p>

                <div class="actions" style="margin-top:25px">
                    <a class="btn btn-primary"
                       href="/request">
                        Start Security Check →
                    </a>

                    <a class="btn btn-dark"
                       href="#how">
                        How it works
                    </a>
                </div>

                <div class="stats-grid">
                    <div class="stat">
                        <strong>01</strong>
                        <span>Submit target</span>
                    </div>

                    <div class="stat">
                        <strong>02</strong>
                        <span>Define scope</span>
                    </div>

                    <div class="stat">
                        <strong>03</strong>
                        <span>Receive report</span>
                    </div>
                </div>
            </div>

            <div class="panel hero-card">
                <div class="status-line">
                    <span class="dot"></span>
                    LIVE SYSTEM
                </div>

                <h2 style="margin-top:0">
                    Security Assessment Console
                </h2>

                <p class="muted">
                    Live request tracking, direct messaging,
                    vulnerability findings and final reporting.
                </p>

                <div style="margin-top:25px">
                    <div class="code-box">
                        TARGET        → HTTPS WEBSITE<br>
                        AUTHORIZATION → REQUIRED<br>
                        SCOPE         → CLIENT DEFINED<br>
                        SCANNING      → MANUAL / AUTHORIZED<br>
                        REPORT        → LIVE PORTAL
                    </div>
                </div>
            </div>

        </div>
    </section>

    <section id="how" class="section">
        <div class="container">
            <h2 class="section-title">How it works</h2>
            <p class="section-sub">
                A simple workflow for authorized website security reviews.
            </p>

            <div class="cards">

                <div class="panel card">
                    <h3>01 · Submit</h3>
                    <p class="muted">
                        Enter your name, email, web name, target and
                        authorized scope.
                    </p>
                </div>

                <div class="panel card">
                    <h3>02 · Review</h3>
                    <p class="muted">
                        The request appears in the private admin console
                        for assessment and communication.
                    </p>
                </div>

                <div class="panel card">
                    <h3>03 · Report</h3>
                    <p class="muted">
                        Findings, severity, evidence and recommendations
                        become available in your private report portal.
                    </p>
                </div>

            </div>
        </div>
    </section>
    """

    return page("Home", body)


# ============================================================
# NEW REQUEST
# ============================================================

@app.route("/request", methods=["GET", "POST"])
def new_request():

    error = ""

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        web_name = request.form.get("web_name", "").strip()
        target = request.form.get("target", "").strip()
        scope = request.form.get("scope", "").strip()
        authorization = request.form.get("authorization")

        if not name:
            error = "Please enter your name."

        elif not email or "@" not in email:
            error = "Please enter a valid email."

        elif not web_name:
            error = "Please enter the website name."

        elif not valid_target(target):
            error = "Target must be a valid HTTP or HTTPS URL."

        elif not scope:
            error = "Please define the authorized scope."

        elif not authorization:
            error = "You must confirm that you are authorized to request testing."

        else:
            client_token = secrets.token_urlsafe(32)
            created = now()
            client_ip = request.headers.get(
                "X-Forwarded-For",
                request.remote_addr or ""
            )

            connection = db()

            cursor = connection.execute(
                """
                INSERT INTO requests (
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
                    client_token,
                    name,
                    email,
                    web_name,
                    target,
                    scope,
                    "PENDING",
                    created,
                    created,
                    client_ip,
                )
            )

            request_id = cursor.lastrowid

            connection.commit()
            connection.close()

            # DNS resolution only. No automatic vulnerability scanning.
            resolved_ip = resolve_target(target)

            if resolved_ip:
                print(
                    f"[MATIA SECURITY CHECK] "
                    f"{target} -> {resolved_ip}"
                )
            else:
                print(
                    f"[MATIA SECURITY CHECK] "
                    f"DNS resolution failed for {target}"
                )

            socketio.emit(
                "request_new",
                {
                    "id": request_id,
                    "name": name,
                    "web_name": web_name,
                    "target": target,
                },
                room="admin"
            )

            return redirect(
                url_for(
                    "client_status",
                    request_id=request_id,
                    token=client_token
                )
            )

    error_html = ""

    if error:
        error_html = f"""
        <div class="notice error">
            {esc(error)}
        </div>
        """

    body = f"""
    <section class="section">
        <div class="container form-wrap">

            <div style="margin-bottom:25px">
                <div class="status-line">
                    <span class="dot"></span>
                    NEW SECURITY REQUEST
                </div>

                <h1 class="section-title" style="font-size:42px">
                    Start an authorized assessment
                </h1>

                <p class="section-sub">
                    Tell us what website you want reviewed and exactly
                    what is inside the authorized scope.
                </p>
            </div>

            <div class="panel form-panel">

                {error_html}

                <form method="POST">

                    <div class="form-grid">

                        <div class="field">
                            <label>Your Name</label>
                            <input
                                name="name"
                                type="text"
                                placeholder="Matia Becolli"
                                required
                            >
                        </div>

                        <div class="field">
                            <label>Your Email</label>
                            <input
                                name="email"
                                type="email"
                                placeholder="you@example.com"
                                required
                            >
                        </div>

                        <div class="field">
                            <label>Web Name</label>
                            <input
                                name="web_name"
                                type="text"
                                placeholder="My Website"
                                required
                            >
                        </div>

                        <div class="field">
                            <label>Web Target</label>
                            <input
                                name="target"
                                type="url"
                                placeholder="https://example.com"
                                required
                            >
                        </div>

                        <div class="field full">
                            <label>Authorized Scope</label>
                            <textarea
                                name="scope"
                                placeholder="Example: public website only, no third-party services, no destructive testing."
                                required
                            ></textarea>
                        </div>

                        <div class="field full">
                            <label class="checkbox">
                                <input
                                    type="checkbox"
                                    name="authorization"
                                    required
                                >
                                <span>
                                    I confirm that I own this website
                                    or have explicit authorization from
                                    the owner to request this security
                                    assessment.
                                </span>
                            </label>
                        </div>

                        <div class="field full">
                            <button
                                class="btn btn-primary"
                                type="submit"
                            >
                                SEND SECURITY REQUEST →
                            </button>
                        </div>

                    </div>

                </form>

            </div>
        </div>
    </section>
    """

    return page("New Request", body)


# ============================================================
# CLIENT STATUS / PORTAL
# ============================================================

@app.route("/status/<int:request_id>")
def client_status(request_id):

    token = request.args.get("token", "")

    if not client_authorized(request_id, token):
        abort(403)

    item = get_request(request_id)

    if not item:
        abort(404)

    connection = db()

    messages = connection.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    message_html = ""

    for message in messages:
        sender_class = (
            "admin"
            if message["sender"] == "admin"
            else "client"
        )

        message_html += f"""
        <div class="msg {sender_class}">
            <div class="who">{esc(message["sender"])}</div>
            <div>{esc(message["message"])}</div>
            <div class="time">
                {esc(message["created_at"])}
            </div>
        </div>
        """

    if not message_html:
        message_html = """
        <div class="empty">
            No messages yet. Your security analyst can reply here.
        </div>
        """

    findings_html = ""

    if findings:

        for finding in findings:
            sev = severity_class(finding["severity"])

            findings_html += f"""
            <div class="panel finding">

                <div class="finding-header">
                    <div>
                        <div class="severity {sev}">
                            {esc(finding["severity"])}
                        </div>

                        <h3>{esc(finding["title"])}</h3>
                    </div>

                    <span class="muted">
                        #{finding["id"]}
                    </span>
                </div>

                <p class="muted">
                    <strong>Description</strong><br>
                    {esc(finding["description"])}
                </p>

                <p class="muted">
                    <strong>Evidence</strong><br>
                    {esc(finding["evidence"])}
                </p>

                <p class="muted">
                    <strong>Recommendation</strong><br>
                    {esc(finding["recommendation"])}
                </p>

            </div>
            """
    else:
        findings_html = """
        <div class="panel empty">
            No findings have been published yet.
        </div>
        """

    script = f"""
    const socket = io();

    socket.on("connect", () => {{
        socket.emit("join_request", {{
            request_id: {request_id}
        }});
    }});

    socket.on("new_message", (data) => {{
        if (data.request_id !== {request_id}) return;

        const box = document.getElementById("chat-box");

        box.insertAdjacentHTML(
            "beforeend",
            `
            <div class="msg admin">
                <div class="who">${{escapeHtml(data.sender)}}</div>
                <div>${{escapeHtml(data.message)}}</div>
                <div class="time">
                    ${{escapeHtml(data.created_at)}}
                </div>
            </div>
            `
        );

        box.scrollTop = box.scrollHeight;

        if (
            "Notification" in window &&
            Notification.permission === "granted"
        ) {{
            new Notification("MATIA // SECURITY CHECK", {{
                body: "New message from your security analyst."
            }});
        }}
    }});

    socket.on("finding_new", (data) => {{
        if (data.request_id !== {request_id}) return;

        if (
            "Notification" in window &&
            Notification.permission === "granted"
        ) {{
            new Notification("New Security Finding", {{
                body: data.title + " · " + data.severity
            }});
        }}

        location.reload();
    }});

    socket.on("report_ready", (data) => {{
        if (data.request_id !== {request_id}) return;

        if (
            "Notification" in window &&
            Notification.permission === "granted"
        ) {{
            new Notification("Security Report Updated", {{
                body: "Your security report has been updated."
            }});
        }}

        location.reload();
    }});

    function escapeHtml(str) {{
        return String(str)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }}

    async function requestNotifications() {{
        if ("Notification" in window) {{
            await Notification.requestPermission();
        }}
    }}

    requestNotifications();
    """

    body = f"""
    <section class="section">
        <div class="container">

            <div class="report-head">

                <div>
                    <div class="status-line">
                        <span class="dot"></span>
                        CLIENT SECURITY PORTAL
                    </div>

                    <h1 class="section-title">
                        {esc(item["web_name"])}
                    </h1>

                    <p class="muted">
                        Request #{item["id"]}
                        · {esc(item["target"])}
                    </p>
                </div>

                <div>
                    <span class="badge {item["status"].lower()}">
                        {esc(item["status"])}
                    </span>
                </div>

            </div>

            <div class="kpi-grid" style="margin-bottom:18px">

                <div class="panel kpi">
                    <strong>#{item["id"]}</strong>
                    <span>Request ID</span>
                </div>

                <div class="panel kpi">
                    <strong>{esc(len(findings))}</strong>
                    <span>Published findings</span>
                </div>

                <div class="panel kpi">
                    <strong>
                        {esc(resolve_target(item["target"]) or "N/A")}
                    </strong>
                    <span>Resolved IP</span>
                </div>

                <div class="panel kpi">
                    <strong>LIVE</strong>
                    <span>Portal connection</span>
                </div>

            </div>

            <div class="dashboard-grid">

                <div>

                    <div class="panel card" style="margin-bottom:18px">
                        <h3>Assessment details</h3>

                        <p class="muted">
                            <strong>Name:</strong>
                            {esc(item["name"])}
                        </p>

                        <p class="muted">
                            <strong>Email:</strong>
                            {esc(item["email"])}
                        </p>

                        <p class="muted">
                            <strong>Web Name:</strong>
                            {esc(item["web_name"])}
                        </p>

                        <p class="muted">
                            <strong>Target:</strong>
                            {esc(item["target"])}
                        </p>

                        <p class="muted">
                            <strong>Scope:</strong><br>
                            {esc(item["scope"])}
                        </p>
                    </div>

                    <div>
                        <h2 class="section-title">
                            Security Findings
                        </h2>

                        {findings_html}
                    </div>

                </div>

                <div class="panel chat">

                    <div style="padding:20px;border-bottom:1px solid var(--border)">
                        <h3 style="margin:0">
                            Live Analyst Chat
                        </h3>

                        <p class="muted" style="margin:7px 0 0">
                            Messages appear instantly.
                        </p>
                    </div>

                    <div class="chat-box" id="chat-box">
                        {message_html}
                    </div>

                    <form
                        class="chat-form"
                        method="POST"
                        action="/status/{request_id}/message?token={esc(token)}"
                    >
                        <input
                            name="message"
                            placeholder="Type a message..."
                            autocomplete="off"
                            required
                        >

                        <button class="btn btn-primary">
                            Send
                        </button>
                    </form>

                </div>

            </div>

        </div>
    </section>
    """

    return page(
        f"Client Portal #{request_id}",
        body,
        script
    )


@app.route("/status/<int:request_id>/message", methods=["POST"])
def client_message(request_id):

    token = request.args.get("token", "")

    if not client_authorized(request_id, token):
        abort(403)

    message = request.form.get("message", "").strip()

    if not message:
        return redirect(
            url_for(
                "client_status",
                request_id=request_id,
                token=token
            )
        )

    created = now()

    connection = db()

    connection.execute(
        """
        INSERT INTO messages (
            request_id,
            sender,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            "client",
            message,
            created,
        )
    )

    connection.commit()
    connection.close()

    socketio.emit(
        "new_message",
        {
            "request_id": request_id,
            "sender": "client",
            "message": message,
            "created_at": created,
        },
        room=f"request_{request_id}"
    )

    socketio.emit(
        "admin_message",
        {
            "request_id": request_id,
            "message": message,
            "created_at": created,
        },
        room="admin"
    )

    return redirect(
        url_for(
            "client_status",
            request_id=request_id,
            token=token
        )
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    error = ""

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True

            return redirect(url_for("admin_dashboard"))

        error = "Invalid admin credentials."

    error_html = ""

    if error:
        error_html = f"""
        <div class="notice error">
            {esc(error)}
        </div>
        """

    body = f"""
    <section class="login">

        <div class="status-line">
            <span class="dot"></span>
            PRIVATE ADMIN ACCESS
        </div>

        <div class="panel login-panel">

            <h1 style="margin-top:0">
                Admin Console
            </h1>

            <p class="muted">
                MATIA // SECURITY CHECK
            </p>

            {error_html}

            <form method="POST">

                <div class="field" style="margin-bottom:15px">
                    <label>Admin Email</label>

                    <input
                        name="email"
                        type="email"
                        placeholder="Admin email"
                        required
                    >
                </div>

                <div class="field" style="margin-bottom:20px">
                    <label>Password</label>

                    <input
                        name="password"
                        type="password"
                        placeholder="Admin password"
                        required
                    >
                </div>

                <button
                    class="btn btn-primary"
                    type="submit"
                    style="width:100%"
                >
                    ENTER ADMIN CONSOLE
                </button>

            </form>

        </div>

    </section>
    """

    return page("Admin Login", body)


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    connection = db()

    requests_list = connection.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    total = connection.execute(
        "SELECT COUNT(*) AS c FROM requests"
    ).fetchone()["c"]

    pending = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM requests
        WHERE status = 'PENDING'
        """
    ).fetchone()["c"]

    progress = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM requests
        WHERE status = 'IN PROGRESS'
        """
    ).fetchone()["c"]

    findings = connection.execute(
        """
        SELECT COUNT(*) AS c
        FROM findings
        """
    ).fetchone()["c"]

    connection.close()

    rows = ""

    for item in requests_list:

        status = item["status"].lower()

        rows += f"""
        <tr>
            <td>#{item["id"]}</td>

            <td>
                <strong>{esc(item["web_name"])}</strong><br>
                <span class="muted">
                    {esc(item["name"])}
                </span>
            </td>

            <td>{esc(item["email"])}</td>

            <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis">
                {esc(item["target"])}
            </td>

            <td>
                <span class="badge {status}">
                    {esc(item["status"])}
                </span>
            </td>

            <td>
                <a
                    class="btn btn-dark"
                    href="/admin/request/{item["id"]}"
                >
                    Open
                </a>
            </td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="6">
                <div class="empty">
                    No requests yet.
                </div>
            </td>
        </tr>
        """

    script = """
    const socket = io();

    socket.on("connect", () => {
        socket.emit("join_admin");
    });

    socket.on("request_new", (data) => {

        if (
            "Notification" in window &&
            Notification.permission === "granted"
        ) {
            new Notification(
                "New Security Request",
                {
                    body:
                        data.web_name +
                        " · " +
                        data.target
                }
            );
        }

        location.reload();
    });

    socket.on("admin_message", (data) => {

        if (
            "Notification" in window &&
            Notification.permission === "granted"
        ) {
            new Notification(
                "New Client Message",
                {
                    body:
                        "Request #" +
                        data.request_id
                }
            );
        }
    });

    if (
        "Notification" in window &&
        Notification.permission === "default"
    ) {
        Notification.requestPermission();
    }
    """

    body = f"""
    <section class="section">
        <div class="container">

            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:25px">

                <div>
                    <div class="status-line">
                        <span class="dot"></span>
                        ADMIN CONSOLE ONLINE
                    </div>

                    <h1 class="section-title" style="font-size:42px">
                        Security Operations
                    </h1>

                    <p class="section-sub">
                        Manage authorized requests,
                        communicate with clients and publish findings.
                    </p>
                </div>

                <a
                    class="btn btn-red"
                    href="/admin/logout"
                >
                    Logout
                </a>

            </div>

            <div class="kpi-grid" style="margin-bottom:20px">

                <div class="panel kpi">
                    <strong>{total}</strong>
                    <span>Total requests</span>
                </div>

                <div class="panel kpi">
                    <strong>{pending}</strong>
                    <span>Pending</span>
                </div>

                <div class="panel kpi">
                    <strong>{progress}</strong>
                    <span>In progress</span>
                </div>

                <div class="panel kpi">
                    <strong>{findings}</strong>
                    <span>Total findings</span>
                </div>

            </div>

            <div class="panel">
                <div style="padding:20px">
                    <h2 style="margin:0">
                        Assessment Requests
                    </h2>
                </div>

                <div class="table-wrap">

                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Website</th>
                                <th>Email</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>

                        <tbody>
                            {rows}
                        </tbody>
                    </table>

                </div>
            </div>

        </div>
    </section>
    """

    return page(
        "Admin Console",
        body,
        script
    )


# ============================================================
# ADMIN REQUEST PAGE
# ============================================================

@app.route("/admin/request/<int:request_id>", methods=["GET", "POST"])
@admin_required
def admin_request(request_id):

    item = get_request(request_id)

    if not item:
        abort(404)

    if request.method == "POST":

        new_status = request.form.get("status")

        allowed = {
            "PENDING",
            "ACCEPTED",
            "IN PROGRESS",
            "COMPLETED",
            "DECLINED",
        }

        if new_status in allowed:

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    new_status,
                    now(),
                    request_id,
                )
            )

            connection.commit()
            connection.close()

            socketio.emit(
                "report_ready",
                {
                    "request_id": request_id,
                    "status": new_status,
                },
                room=f"request_{request_id}"
            )

    connection = db()

    messages = connection.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    message_html = ""

    for message in messages:

        sender_class = (
            "admin"
            if message["sender"] == "admin"
            else "client"
        )

        message_html += f"""
        <div class="msg {sender_class}">
            <div class="who">
                {esc(message["sender"])}
            </div>

            <div>
                {esc(message["message"])}
            </div>

            <div class="time">
                {esc(message["created_at"])}
            </div>
        </div>
        """

    if not message_html:
        message_html = """
        <div class="empty">
            No messages yet.
        </div>
        """

    finding_html = ""

    for finding in findings:

        sev = severity_class(
            finding["severity"]
        )

        finding_html += f"""
        <div class="panel finding">

            <div class="finding-header">

                <div>
                    <div class="severity {sev}">
                        {esc(finding["severity"])}
                    </div>

                    <h3>
                        {esc(finding["title"])}
                    </h3>
                </div>

                <span class="muted">
                    #{finding["id"]}
                </span>

            </div>

            <p class="muted">
                <strong>Description</strong><br>
                {esc(finding["description"])}
            </p>

            <p class="muted">
                <strong>Evidence</strong><br>
                {esc(finding["evidence"])}
            </p>

            <p class="muted">
                <strong>Recommendation</strong><br>
                {esc(finding["recommendation"])}
            </p>

        </div>
        """

    if not finding_html:
        finding_html = """
        <div class="panel empty">
            No findings published.
        </div>
        """

    script = f"""
    const socket = io();

    socket.on("connect", () => {{
        socket.emit("join_admin");
        socket.emit("join_request", {{
            request_id: {request_id}
        }});
    }});

    socket.on("new_message", (data) => {{

        if (data.request_id !== {request_id}) return;

        const box =
            document.getElementById("admin-chat-box");

        box.insertAdjacentHTML(
            "beforeend",
            `
            <div class="msg client">
                <div class="who">${{escapeHtml(data.sender)}}</div>
                <div>${{escapeHtml(data.message)}}</div>
                <div class="time">
                    ${{escapeHtml(data.created_at)}}
                </div>
            </div>
            `
        );

        box.scrollTop = box.scrollHeight;
    }});

    function escapeHtml(str) {{
        return String(str)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }}
    """

    body = f"""
    <section class="section">
        <div class="container">

            <div style="margin-bottom:22px">
                <div class="status-line">
                    <span class="dot"></span>
                    REQUEST #{request_id}
                </div>

                <h1 class="section-title">
                    {esc(item["web_name"])}
                </h1>

                <p class="muted">
                    {esc(item["target"])}
                </p>
            </div>

            <div class="dashboard-grid">

                <div>

                    <div class="panel card" style="margin-bottom:18px">

                        <h3>
                            Client Information
                        </h3>

                        <p class="muted">
                            <strong>Name:</strong>
                            {esc(item["name"])}
                        </p>

                        <p class="muted">
                            <strong>Email:</strong>
                            {esc(item["email"])}
                        </p>

                        <p class="muted">
                            <strong>Web Name:</strong>
                            {esc(item["web_name"])}
                        </p>

                        <p class="muted">
                            <strong>Target:</strong>
                            {esc(item["target"])}
                        </p>

                        <p class="muted">
                            <strong>Scope:</strong><br>
                            {esc(item["scope"])}
                        </p>

                        <p class="muted">
                            <strong>DNS:</strong>
                            {esc(resolve_target(item["target"]) or "Not resolved")}
                        </p>

                        <p class="muted">
                            <strong>Created:</strong>
                            {esc(item["created_at"])}
                        </p>

                    </div>

                    <div class="panel card" style="margin-bottom:18px">

                        <h3>
                            Change Request Status
                        </h3>

                        <form
                            method="POST"
                            style="display:flex;gap:10px;flex-wrap:wrap"
                        >

                            <select name="status">

                                <option
                                    {"selected" if item["status"] == "PENDING" else ""}
                                >
                                    PENDING
                                </option>

                                <option
                                    {"selected" if item["status"] == "ACCEPTED" else ""}
                                >
                                    ACCEPTED
                                </option>

                                <option
                                    {"selected" if item["status"] == "IN PROGRESS" else ""}
                                >
                                    IN PROGRESS
                                </option>

                                <option
                                    {"selected" if item["status"] == "COMPLETED" else ""}
                                >
                                    COMPLETED
                                </option>

                                <option
                                    {"selected" if item["status"] == "DECLINED" else ""}
                                >
                                    DECLINED
                                </option>

                            </select>

                            <button class="btn btn-primary">
                                Update Status
                            </button>

                        </form>

                    </div>

                    <div>
                        <h2 class="section-title">
                            Findings
                        </h2>

                        {finding_html}
                    </div>

                </div>

                <div class="panel chat">

                    <div style="padding:20px;border-bottom:1px solid var(--border)">
                        <h3 style="margin:0">
                            Client Chat
                        </h3>

                        <p class="muted" style="margin:7px 0 0">
                            Live communication.
                        </p>
                    </div>

                    <div
                        class="chat-box"
                        id="admin-chat-box"
                    >
                        {message_html}
                    </div>

                    <form
                        class="chat-form"
                        method="POST"
                        action="/admin/request/{request_id}/message"
                    >
                        <input
                            name="message"
                            placeholder="Reply to client..."
                            autocomplete="off"
                            required
                        >

                        <button class="btn btn-primary">
                            Send
                        </button>
                    </form>

                </div>

            </div>

            <div style="margin-top:20px">

                <div class="panel card">

                    <h2 style="margin-top:0">
                        Publish Finding
                    </h2>

                    <form
                        method="POST"
                        action="/admin/request/{request_id}/finding"
                    >

                        <div class="form-grid">

                            <div class="field">
                                <label>Finding Title</label>

                                <input
                                    name="title"
                                    placeholder="Information Disclosure"
                                    required
                                >
                            </div>

                            <div class="field">
                                <label>Severity</label>

                                <select
                                    name="severity"
                                    required
                                >
                                    <option>INFO</option>
                                    <option>LOW</option>
                                    <option>MEDIUM</option>
                                    <option>HIGH</option>
                                    <option>CRITICAL</option>
                                </select>
                            </div>

                            <div class="field full">
                                <label>Description</label>

                                <textarea
                                    name="description"
                                    placeholder="Explain the finding..."
                                    required
                                ></textarea>
                            </div>

                            <div class="field full">
                                <label>Evidence</label>

                                <textarea
                                    name="evidence"
                                    placeholder="Describe the evidence..."
                                    required
                                ></textarea>
                            </div>

                            <div class="field full">
                                <label>Recommendation</label>

                                <textarea
                                    name="recommendation"
                                    placeholder="Explain how the client can fix it..."
                                    required
                                ></textarea>
                            </div>

                            <div class="field full">

                                <button
                                    class="btn btn-green"
                                    type="submit"
                                >
                                    PUBLISH FINDING
                                </button>

                            </div>

                        </div>

                    </form>

                </div>

            </div>

            <div style="margin-top:20px">

                <a
                    class="btn btn-dark"
                    href="/admin/report/{request_id}"
                >
                    View Full Report →
                </a>

                <a
                    class="btn btn-dark"
                    href="/admin"
                >
                    ← Back to Dashboard
                </a>

            </div>

        </div>
    </section>
    """

    return page(
        f"Request #{request_id}",
        body,
        script
    )


@app.route("/admin/request/<int:request_id>/message", methods=["POST"])
@admin_required
def admin_message(request_id):

    message = request.form.get(
        "message",
        ""
    ).strip()

    if not message:
        return redirect(
            url_for(
                "admin_request",
                request_id=request_id
            )
        )

    created = now()

    connection = db()

    connection.execute(
        """
        INSERT INTO messages (
            request_id,
            sender,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            "admin",
            message,
            created,
        )
    )

    connection.commit()
    connection.close()

    socketio.emit(
        "new_message",
        {
            "request_id": request_id,
            "sender": "admin",
            "message": message,
            "created_at": created,
        },
        room=f"request_{request_id}"
    )

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id
        )
    )


@app.route("/admin/request/<int:request_id>/finding", methods=["POST"])
@admin_required
def add_finding(request_id):

    title = request.form.get(
        "title",
        ""
    ).strip()

    severity = request.form.get(
        "severity",
        "INFO"
    ).strip().upper()

    description = request.form.get(
        "description",
        ""
    ).strip()

    evidence = request.form.get(
        "evidence",
        ""
    ).strip()

    recommendation = request.form.get(
        "recommendation",
        ""
    ).strip()

    allowed_severity = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    if severity not in allowed_severity:
        abort(400)

    if not title or not description or not evidence or not recommendation:
        abort(400)

    connection = db()

    cursor = connection.execute(
        """
        INSERT INTO findings (
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
        )
    )

    connection.commit()

    finding_id = cursor.lastrowid

    connection.close()

    socketio.emit(
        "finding_new",
        {
            "request_id": request_id,
            "finding_id": finding_id,
            "title": title,
            "severity": severity,
        },
        room=f"request_{request_id}"
    )

    socketio.emit(
        "report_ready",
        {
            "request_id": request_id
        },
        room=f"request_{request_id}"
    )

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id
        )
    )


# ============================================================
# ADMIN REPORT
# ============================================================

@app.route("/admin/report/<int:request_id>")
@admin_required
def admin_report(request_id):

    item = get_request(request_id)

    if not item:
        abort(404)

    connection = db()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    findings_html = ""

    for finding in findings:

        sev = severity_class(
            finding["severity"]
        )

        findings_html += f"""
        <div class="panel finding">

            <div class="finding-header">

                <div>
                    <div class="severity {sev}">
                        {esc(finding["severity"])}
                    </div>

                    <h3>
                        {esc(finding["title"])}
                    </h3>
                </div>

                <span class="muted">
                    #{finding["id"]}
                </span>

            </div>

            <p>
                <strong>Description</strong><br>
                <span class="muted">
                    {esc(finding["description"])}
                </span>
            </p>

            <p>
                <strong>Evidence</strong><br>
                <span class="muted">
                    {esc(finding["evidence"])}
                </span>
            </p>

            <p>
                <strong>Recommendation</strong><br>
                <span class="muted">
                    {esc(finding["recommendation"])}
                </span>
            </p>

        </div>
        """

    if not findings_html:
        findings_html = """
        <div class="panel empty">
            No findings are included in this report yet.
        </div>
        """

    body = f"""
    <section class="section">
        <div class="container">

            <div class="report-head">

                <div>
                    <div class="status-line">
                        <span class="dot"></span>
                        SECURITY REPORT
                    </div>

                    <h1 class="section-title">
                        {esc(item["web_name"])}
                    </h1>

                    <p class="muted">
                        Request #{item["id"]}
                    </p>
                </div>

                <div class="actions">
                    <a
                        class="btn btn-dark"
                        href="/admin/request/{request_id}"
                    >
                        ← Back
                    </a>
                </div>

            </div>

            <div class="panel card" style="margin-bottom:18px">

                <h2 style="margin-top:0">
                    Assessment Overview
                </h2>

                <p class="muted">
                    <strong>Client:</strong>
                    {esc(item["name"])}
                </p>

                <p class="muted">
                    <strong>Email:</strong>
                    {esc(item["email"])}
                </p>

                <p class="muted">
                    <strong>Website:</strong>
                    {esc(item["web_name"])}
                </p>

                <p class="muted">
                    <strong>Target:</strong>
                    {esc(item["target"])}
                </p>

                <p class="muted">
                    <strong>Scope:</strong><br>
                    {esc(item["scope"])}
                </p>

                <p class="muted">
                    <strong>Status:</strong>
                    {esc(item["status"])}
                </p>

            </div>

            <h2 class="section-title">
                Findings
            </h2>

            {findings_html}

        </div>
    </section>
    """

    return page(
        f"Report #{request_id}",
        body
    )


# ============================================================
# CLIENT REPORT
# ============================================================

@app.route("/report/<int:request_id>")
def client_report(request_id):

    token = request.args.get("token", "")

    if not client_authorized(request_id, token):
        abort(403)

    item = get_request(request_id)

    if not item:
        abort(404)

    connection = db()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    findings_html = ""

    for finding in findings:

        sev = severity_class(
            finding["severity"]
        )

        findings_html += f"""
        <div class="panel finding">

            <div class="finding-header">

                <div>
                    <div class="severity {sev}">
                        {esc(finding["severity"])}
                    </div>

                    <h3>
                        {esc(finding["title"])}
                    </h3>
                </div>

            </div>

            <p class="muted">
                <strong>Description</strong><br>
                {esc(finding["description"])}
            </p>

            <p class="muted">
                <strong>Evidence</strong><br>
                {esc(finding["evidence"])}
            </p>

            <p class="muted">
                <strong>Recommendation</strong><br>
                {esc(finding["recommendation"])}
            </p>

        </div>
        """

    if not findings_html:
        findings_html = """
        <div class="panel empty">
            Your report does not contain published findings yet.
        </div>
        """

    body = f"""
    <section class="section">
        <div class="container">

            <div class="report-head">

                <div>
                    <div class="status-line">
                        <span class="dot"></span>
                        PRIVATE SECURITY REPORT
                    </div>

                    <h1 class="section-title">
                        {esc(item["web_name"])}
                    </h1>

                    <p class="muted">
                        {esc(item["target"])}
                    </p>
                </div>

                <span class="badge {item["status"].lower()}">
                    {esc(item["status"])}
                </span>

            </div>

            <div class="panel card" style="margin-bottom:20px">

                <h2 style="margin-top:0">
                    Executive Summary
                </h2>

                <p class="muted">
                    This report contains security findings that have
                    been published by the assessment administrator.
                    The assessment is limited to the authorized scope
                    supplied with this request.
                </p>

            </div>

            <h2 class="section-title">
                Security Findings
            </h2>

            {findings_html}

            <div style="margin-top:20px">

                <a
                    class="btn btn-dark"
                    href="/status/{request_id}?token={esc(token)}"
                >
                    ← Back to Portal
                </a>

            </div>

        </div>
    </section>
    """

    return page(
        f"Client Report #{request_id}",
        body
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# ERROR PAGES
# ============================================================

@app.errorhandler(403)
def forbidden(_error):

    body = """
    <section class="section">
        <div class="container" style="max-width:700px">

            <div class="panel card" style="text-align:center">

                <div style="font-size:60px">
                    🔒
                </div>

                <h1>
                    Access denied
                </h1>

                <p class="muted">
                    This portal link is private or invalid.
                </p>

                <a
                    class="btn btn-primary"
                    href="/"
                >
                    Return Home
                </a>

            </div>

        </div>
    </section>
    """

    return page(
        "Access Denied",
        body
    ), 403


@app.errorhandler(404)
def not_found(_error):

    body = """
    <section class="section">
        <div class="container" style="max-width:700px">

            <div class="panel card" style="text-align:center">

                <div style="font-size:60px">
                    🛰️
                </div>

                <h1>
                    Page not found
                </h1>

                <p class="muted">
                    The requested security portal page does not exist.
                </p>

                <a
                    class="btn btn-primary"
                    href="/"
                >
                    Return Home
                </a>

            </div>

        </div>
    </section>
    """

    return page(
        "Not Found",
        body
    ), 404


# ============================================================
# STARTUP
# ============================================================

init_db()

if __name__ == "__main__":

    print("")
    print("==============================================")
    print("      MATIA // SECURITY CHECK")
    print("==============================================")
    print("")
    print(f"[+] Admin email: {ADMIN_EMAIL}")
    print("[+] Database: connected")
    print("[+] Automatic scanning: DISABLED")
    print("[+] DNS resolution: ENABLED")
    print("[+] Live Socket.IO: ENABLED")
    print("")
    print(f"[+] Server starting on port {PORT}")
    print("")

    socketio.run(
        app,
        host="0.0.0.0",
        port=PORT,
        allow_unsafe_werkzeug=True
    )
