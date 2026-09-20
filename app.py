import os
import re
import hmac
import html
import json
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
    jsonify,
    abort,
)

# ============================================================
# MATIA // SECURITY CHECK
# DARK SOC EDITION
# ============================================================

APP_NAME = "MATIA // SECURITY CHECK"
VERSION = "4.0-SOC"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "MATIA_DB_PATH",
    os.path.join(BASE_DIR, "matia_security.db")
)

SECRET_KEY = os.environ.get("MATIA_SECRET_KEY", "")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

OWNER_EMAIL = os.environ.get("MATIA_OWNER_EMAIL", "owner@example.com")
OWNER_PASSWORD = os.environ.get("MATIA_OWNER_PASSWORD", "CHANGE_ME")

ADMIN_EMAIL = os.environ.get("MATIA_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "CHANGE_ME")

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# ============================================================
# CONSTANTS
# ============================================================

PENDING = "PENDING"
ACCEPTED = "ACCEPTED"
DECLINED = "DECLINED"
IN_PROGRESS = "IN PROGRESS"
COMPLETED = "COMPLETED"

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

OPEN_CHAT_STATUSES = {
    ACCEPTED,
    IN_PROGRESS,
    COMPLETED,
}

STATUS_ORDER = [
    PENDING,
    ACCEPTED,
    IN_PROGRESS,
    COMPLETED,
    DECLINED,
]

# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row

    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
    except Exception:
        pass

    return conn


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_db():
    conn = db()

    conn.execute("""
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
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            recommendation TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            audience TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            request_id INTEGER,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_request
        ON messages(request_id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_audience
        ON notifications(audience, read, id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_findings_request
        ON findings(request_id)
    """)

    conn.commit()
    conn.close()


init_db()

# ============================================================
# SECURITY / HELPERS
# ============================================================

def clean_text(value, max_len=4000):
    if value is None:
        return ""

    value = str(value).strip()

    if len(value) > max_len:
        value = value[:max_len]

    return value


def valid_email(value):
    return bool(
        re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            value or ""
        )
    )


def valid_target(value):
    return bool(
        re.match(
            r"^https?://[^\s]+$",
            value or "",
            re.IGNORECASE
        )
    )


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def current_role():
    return session.get("role")


def role_required(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_role() != role:
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def staff_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_role() not in {"admin", "owner"}:
            return redirect(url_for("admin_login"))

        return fn(*args, **kwargs)

    return wrapper


def get_request(request_id):
    conn = db()

    row = conn.execute(
        "SELECT * FROM requests WHERE id=?",
        (request_id,)
    ).fetchone()

    conn.close()

    return row


def get_request_by_token(request_id, token):
    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id=? AND client_token=?
        """,
        (request_id, token)
    ).fetchone()

    conn.close()

    return row


def stats():
    conn = db()

    data = {}

    for status in STATUS_ORDER:
        data[status] = conn.execute(
            "SELECT COUNT(*) c FROM requests WHERE status=?",
            (status,)
        ).fetchone()["c"]

    data["total"] = conn.execute(
        "SELECT COUNT(*) c FROM requests"
    ).fetchone()["c"]

    data["findings"] = conn.execute(
        "SELECT COUNT(*) c FROM findings"
    ).fetchone()["c"]

    conn.close()

    return data


def notify(
    audience,
    kind,
    title,
    body,
    request_id=None
):
    conn = db()

    conn.execute(
        """
        INSERT INTO notifications
        (request_id, audience, kind, title, body, created_at, read)
        VALUES (?, ?, ?, ?, ?, ?, 0)
        """,
        (
            request_id,
            audience,
            kind,
            title,
            body,
            now(),
        )
    )

    conn.commit()
    conn.close()


def notify_staff(
    kind,
    title,
    body,
    request_id=None
):
    notify(
        "staff",
        kind,
        title,
        body,
        request_id
    )


def notify_client(
    request_id,
    kind,
    title,
    body
):
    notify(
        f"client:{request_id}",
        kind,
        title,
        body,
        request_id
    )


def add_message(request_id, sender, message):
    conn = db()

    conn.execute(
        """
        INSERT INTO messages
        (request_id, sender, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            sender,
            message,
            now(),
        )
    )

    conn.commit()
    conn.close()


def system_message(request_id, message):
    add_message(
        request_id,
        "SYSTEM",
        message
    )


def audit_action(actor, action, request_id=None):
    conn = db()

    conn.execute(
        """
        INSERT INTO audit_log
        (actor, action, request_id, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            actor,
            action,
            request_id,
            now(),
        )
    )

    conn.commit()
    conn.close()


def set_status(request_id, new_status, actor):
    row = get_request(request_id)

    if not row:
        return False, "Client not found."

    old_status = row["status"]

    allowed = {
        PENDING: {ACCEPTED, DECLINED},
        ACCEPTED: {IN_PROGRESS, DECLINED},
        IN_PROGRESS: {COMPLETED, ACCEPTED},
        COMPLETED: {IN_PROGRESS},
        DECLINED: {PENDING, ACCEPTED},
    }

    if new_status not in allowed.get(old_status, set()):
        return False, f"Cannot change {old_status} → {new_status}"

    conn = db()

    conn.execute(
        """
        UPDATE requests
        SET status=?, updated_at=?
        WHERE id=?
        """,
        (
            new_status,
            now(),
            request_id,
        )
    )

    conn.commit()
    conn.close()

    audit_action(
        actor,
        f"STATUS {old_status} -> {new_status}",
        request_id
    )

    system_message(
        request_id,
        f"{actor.upper()} changed status to {new_status}."
    )

    notify_client(
        request_id,
        "status",
        f"Request {new_status}",
        f"Your security request is now {new_status}."
    )

    notify_staff(
        "status",
        f"Request #{request_id}",
        f"{actor} changed status to {new_status}.",
        request_id
    )

    return True, "Status updated."


# ============================================================
# GLOBAL SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Cache-Control"] = "no-store"

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template_string("""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MATIA // SECURITY CHECK</title>

<style>
*{box-sizing:border-box}

body{
    margin:0;
    min-height:100vh;
    background:
        radial-gradient(circle at 20% 20%,rgba(0,255,180,.09),transparent 30%),
        radial-gradient(circle at 80% 70%,rgba(90,70,255,.12),transparent 35%),
        #05070b;
    color:#e9fdf7;
    font-family:Inter,Segoe UI,Arial,sans-serif;
}

.wrap{
    max-width:1150px;
    margin:auto;
    padding:80px 25px;
}

.logo{
    font-size:18px;
    letter-spacing:5px;
    color:#65ffd1;
    font-weight:900;
}

h1{
    font-size:64px;
    line-height:1;
    margin:25px 0;
}

p{
    color:#8da39f;
    font-size:18px;
    line-height:1.7;
}

.actions{
    display:flex;
    gap:15px;
    flex-wrap:wrap;
    margin-top:35px;
}

a{
    text-decoration:none;
    color:white;
    padding:15px 23px;
    border-radius:14px;
    background:#101820;
    border:1px solid #20332f;
}

.primary{
    background:#35d9a1;
    color:#04100c;
    font-weight:900;
}

.grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:18px;
    margin-top:70px;
}

.card{
    background:rgba(10,17,22,.8);
    border:1px solid #1b302d;
    padding:25px;
    border-radius:20px;
}

.card b{
    color:#65ffd1;
}

@media(max-width:800px){
    h1{font-size:43px}
    .grid{grid-template-columns:1fr}
}
</style>
</head>

<body>
<div class="wrap">

<div class="logo">MATIA // SECURITY CHECK</div>

<h1>Authorized Security<br>Operations.</h1>

<p>
Professional security request management,
secure client communication and live
assessment operations.
</p>

<div class="actions">
<a class="primary" href="/request">REQUEST SECURITY CHECK</a>
<a href="/admin/login">STAFF ACCESS</a>
<a href="/owner/login">OWNER ACCESS</a>
</div>

<div class="grid">
<div class="card">
<b>01 / REQUEST</b>
<p>Submit an authorized security assessment request.</p>
</div>

<div class="card">
<b>02 / REVIEW</b>
<p>Security staff review scope and authorization.</p>
</div>

<div class="card">
<b>03 / LIVE OPS</b>
<p>Communicate with the security team in real time.</p>
</div>
</div>

</div>
</body>
</html>
""")


# ============================================================
# REQUEST
# ============================================================

REQUEST_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>New Security Request</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
background:#05070b;
color:#eafff9;
font-family:Inter,Segoe UI,Arial;
}

.wrap{
max-width:850px;
margin:50px auto;
padding:25px;
}

.logo{
color:#63ffd0;
letter-spacing:4px;
font-weight:900;
}

.panel{
margin-top:30px;
background:#0b1117;
border:1px solid #1b302d;
border-radius:25px;
padding:30px;
box-shadow:0 20px 70px #0008;
}

label{
display:block;
margin:18px 0 8px;
color:#91aaa5;
}

input,textarea{
width:100%;
padding:15px;
border-radius:12px;
border:1px solid #20352f;
background:#05090d;
color:white;
outline:none;
}

textarea{
min-height:120px;
resize:vertical;
}

button{
margin-top:22px;
width:100%;
padding:16px;
border:0;
border-radius:13px;
background:#38dca4;
font-weight:900;
cursor:pointer;
}

.notice{
margin-top:15px;
padding:14px;
border:1px solid #293f3a;
border-radius:12px;
color:#91aaa5;
}
</style>
</head>

<body>

<div class="wrap">

<div class="logo">MATIA // SECURITY CHECK</div>

<div class="panel">

<h1>Security Assessment Request</h1>

<form method="post">

<label>Name</label>
<input name="name" required maxlength="120">

<label>Email</label>
<input name="email" type="email" required maxlength="180">

<label>Website / Project Name</label>
<input name="web_name" required maxlength="160">

<label>Target</label>
<input
name="target"
placeholder="https://example.com"
required
maxlength="500"
>

<label>Authorized Scope</label>
<textarea
name="scope"
required
maxlength="4000"
placeholder="Describe what you own or have explicit permission to test..."
></textarea>

<div class="notice">
Only submit systems you own or have explicit authorization to assess.
</div>

<button type="submit">
CREATE SECURITY REQUEST
</button>

</form>

</div>
</div>

</body>
</html>
"""


@app.route("/request", methods=["GET", "POST"])
def create_request():

    if request.method == "GET":
        return render_template_string(REQUEST_PAGE)

    name = clean_text(request.form.get("name"), 120)
    email = clean_text(request.form.get("email"), 180)
    web_name = clean_text(request.form.get("web_name"), 160)
    target = clean_text(request.form.get("target"), 500)
    scope = clean_text(request.form.get("scope"), 4000)

    if not name or not email or not web_name or not scope:
        abort(400)

    if not valid_email(email):
        abort(400)

    if not valid_target(target):
        abort(400)

    token = secrets.token_urlsafe(32)
    timestamp = now()

    client_ip = request.headers.get(
        "CF-Connecting-IP",
        request.remote_addr or ""
    )

    conn = db()

    cur = conn.execute(
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
            PENDING,
            timestamp,
            timestamp,
            client_ip,
        )
    )

    request_id = cur.lastrowid

    conn.commit()
    conn.close()

    system_message(
        request_id,
        "Security request created. Waiting for staff review."
    )

    notify_staff(
        "request",
        "NEW SECURITY REQUEST",
        f"{name} submitted a new security request.",
        request_id
    )

    audit_action(
        "CLIENT",
        "CREATED REQUEST",
        request_id
    )

    return redirect(
        url_for(
            "client_status",
            request_id=request_id,
            token=token
        )
    )


# ============================================================
# CLIENT PAGE
# ============================================================

CLIENT_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Request #{{ row.id }}</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
background:
radial-gradient(circle at 20% 10%,#00ffc414,transparent 30%),
#05070b;
color:#eafff9;
font-family:Inter,Segoe UI,Arial;
}

.wrap{
max-width:1200px;
margin:auto;
padding:35px 20px;
}

.top{
display:flex;
justify-content:space-between;
align-items:center;
gap:15px;
flex-wrap:wrap;
}

.logo{
color:#61ffd0;
letter-spacing:4px;
font-weight:900;
}

.status{
padding:10px 15px;
border-radius:999px;
background:#0d1818;
border:1px solid #28433d;
color:#63ffd0;
font-weight:900;
}

.grid{
display:grid;
grid-template-columns:1fr 1.4fr;
gap:20px;
margin-top:25px;
}

.card{
background:#0b1117;
border:1px solid #1c302d;
border-radius:22px;
padding:25px;
box-shadow:0 15px 60px #0008;
}

.meta{
display:grid;
gap:12px;
margin-top:20px;
}

.meta div{
padding:14px;
border-radius:13px;
background:#071015;
border:1px solid #172724;
}

.meta span{
display:block;
font-size:11px;
color:#718c87;
text-transform:uppercase;
letter-spacing:2px;
margin-bottom:5px;
}

.chat{
height:530px;
display:flex;
flex-direction:column;
}

.messages{
flex:1;
overflow:auto;
padding:10px;
}

.msg{
max-width:80%;
margin:10px 0;
padding:13px 15px;
border-radius:15px;
background:#111d22;
border:1px solid #1d3530;
}

.msg.client{
margin-left:auto;
background:#14372f;
}

.msg.system{
margin:auto;
text-align:center;
color:#78aaa0;
font-size:13px;
}

.time{
font-size:10px;
color:#66827d;
margin-top:5px;
}

.composer{
display:flex;
gap:10px;
padding-top:15px;
}

.composer input{
flex:1;
background:#05090d;
border:1px solid #1e3731;
border-radius:12px;
padding:14px;
color:white;
}

.composer button{
border:0;
border-radius:12px;
padding:0 22px;
background:#36dca4;
font-weight:900;
}

.live{
color:#63ffd0;
font-size:12px;
letter-spacing:2px;
}

.locked{
height:100%;
display:grid;
place-items:center;
color:#6c8580;
text-align:center;
}

@media(max-width:850px){
.grid{grid-template-columns:1fr}
.chat{height:500px}
}
</style>
</head>

<body>

<div class="wrap">

<div class="top">
<div class="logo">MATIA // SECURITY CHECK</div>
<div id="status" class="status">{{ row.status }}</div>
</div>

<div class="grid">

<div class="card">

<h2>Request #{{ row.id }}</h2>

<div class="meta">

<div>
<span>Client</span>
{{ row.name }}
</div>

<div>
<span>Email</span>
{{ row.email }}
</div>

<div>
<span>Project</span>
{{ row.web_name }}
</div>

<div>
<span>Target</span>
{{ row.target }}
</div>

<div>
<span>Scope</span>
{{ row.scope }}
</div>

</div>

</div>

<div class="card chat">

<div style="display:flex;justify-content:space-between">
<h2 style="margin-top:0">Live Operations</h2>
<div id="live" class="live">● WAITING</div>
</div>

<div id="messages" class="messages"></div>

<div id="composer" class="composer" style="display:none">
<input id="message" placeholder="Write to security staff...">
<button onclick="sendMessage()">SEND</button>
</div>

</div>

</div>

</div>

<script>

const requestId = {{ row.id }};
const token = {{ row.client_token|tojson }};

let lastMessageId = 0;
let audioEnabled = false;
let audioContext = null;

function enableAudio(){

    if(!audioContext){
        audioContext =
            new (window.AudioContext || window.webkitAudioContext)();
    }

    audioContext.resume();
    audioEnabled = true;
}

document.addEventListener("click", enableAudio, {once:true});

function ring(){

    if(!audioEnabled || !audioContext) return;

    const osc = audioContext.createOscillator();
    const gain = audioContext.createGain();

    osc.frequency.value = 880;
    gain.gain.value = 0.035;

    osc.connect(gain);
    gain.connect(audioContext.destination);

    osc.start();

    setTimeout(() => {
        osc.frequency.value = 660;
    }, 120);

    setTimeout(() => {
        osc.stop();
    }, 240);
}

function esc(value){

    const d = document.createElement("div");
    d.textContent = value ?? "";
    return d.innerHTML;
}

function renderMessages(messages){

    const box = document.getElementById("messages");

    const oldBottom =
        box.scrollHeight - box.scrollTop - box.clientHeight < 100;

    box.innerHTML = "";

    for(const m of messages){

        const div = document.createElement("div");

        div.className =
            "msg " +
            (
                m.sender === "CLIENT"
                ? "client"
                : m.sender === "SYSTEM"
                ? "system"
                : ""
            );

        div.innerHTML =
            "<div>" + esc(m.message) + "</div>" +
            "<div class='time'>" +
            esc(m.sender) +
            " • " +
            esc(m.created_at) +
            "</div>";

        box.appendChild(div);
    }

    if(oldBottom){
        box.scrollTop = box.scrollHeight;
    }
}

async function load(){

    try{

        const res = await fetch(
            `/api/client/${requestId}/data?token=${encodeURIComponent(token)}`,
            {cache:"no-store"}
        );

        if(!res.ok) return;

        const data = await res.json();

        document.getElementById("status").textContent =
            data.request.status;

        if(data.request.status === "ACCEPTED" ||
           data.request.status === "IN PROGRESS" ||
           data.request.status === "COMPLETED"){

            document.getElementById("composer").style.display = "flex";
            document.getElementById("live").textContent = "● LIVE CHAT";

        }else{

            document.getElementById("composer").style.display = "none";

            document.getElementById("live").textContent =
                data.request.status === "PENDING"
                ? "● WAITING FOR STAFF"
                : "● " + data.request.status;
        }

        const latest =
            data.messages.length
            ? data.messages[data.messages.length - 1].id
            : 0;

        if(lastMessageId && latest > lastMessageId){
            ring();
        }

        lastMessageId = latest;

        renderMessages(data.messages);

    }catch(e){}
}

async function sendMessage(){

    enableAudio();

    const input =
        document.getElementById("message");

    const message = input.value.trim();

    if(!message) return;

    input.disabled = true;

    try{

        const res = await fetch(
            `/api/client/${requestId}/message?token=${encodeURIComponent(token)}`,
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({message})
            }
        );

        if(res.ok){
            input.value = "";
            await load();
        }

    }finally{
        input.disabled = false;
        input.focus();
    }
}

document
.getElementById("message")
?.addEventListener("keydown", e => {

    if(e.key === "Enter"){
        e.preventDefault();
        sendMessage();
    }

});

load();
setInterval(load,1000);

</script>

</body>
</html>
"""


@app.route("/status/<int:request_id>")
def client_status(request_id):

    token = request.args.get("token", "")

    row = get_request_by_token(
        request_id,
        token
    )

    if not row:
        abort(404)

    return render_template_string(
        CLIENT_PAGE,
        row=row
    )


# ============================================================
# CLIENT API
# ============================================================

@app.route("/api/client/<int:request_id>/data")
def client_data(request_id):

    token = request.args.get("token", "")

    row = get_request_by_token(
        request_id,
        token
    )

    if not row:
        abort(404)

    conn = db()

    messages = conn.execute(
        """
        SELECT id, sender, message, created_at
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = conn.execute(
        """
        SELECT id, title, severity, description,
               evidence, recommendation, created_at
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    return jsonify({
        "request": {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "web_name": row["web_name"],
            "target": row["target"],
            "scope": row["scope"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        },
        "messages": [
            dict(x)
            for x in messages
        ],
        "findings": [
            dict(x)
            for x in findings
        ]
    })


@app.route(
    "/api/client/<int:request_id>/message",
    methods=["POST"]
)
def client_message(request_id):

    token = request.args.get("token", "")

    row = get_request_by_token(
        request_id,
        token
    )

    if not row:
        abort(404)

    if row["status"] not in OPEN_CHAT_STATUSES:
        return jsonify({
            "ok": False,
            "error": "Chat is not open."
        }), 400

    data = request.get_json(silent=True) or {}

    message = clean_text(
        data.get("message"),
        2000
    )

    if not message:
        return jsonify({
            "ok": False,
            "error": "Empty message."
        }), 400

    add_message(
        request_id,
        "CLIENT",
        message
    )

    notify_staff(
        "message",
        f"NEW MESSAGE #{request_id}",
        f"{row['name']}: {message[:160]}",
        request_id
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# LOGIN
# ============================================================

LOGIN_PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{{ title }}</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
min-height:100vh;
display:grid;
place-items:center;
background:
radial-gradient(circle at 50% 0%,#00ffc414,transparent 35%),
#040608;
font-family:Inter,Segoe UI,Arial;
color:#ecfffa;
}

.login{
width:min(430px,calc(100% - 30px));
background:#0a1015;
border:1px solid #20352f;
border-radius:25px;
padding:35px;
box-shadow:0 30px 100px #000b;
}

.logo{
color:#62ffd0;
font-weight:900;
letter-spacing:4px;
}

h1{
font-size:30px;
}

input{
width:100%;
margin:8px 0 15px;
padding:14px;
background:#05090d;
border:1px solid #20352f;
border-radius:12px;
color:white;
}

button{
width:100%;
padding:15px;
border:0;
border-radius:12px;
background:#38dca4;
font-weight:900;
cursor:pointer;
}

.error{
background:#321419;
border:1px solid #692630;
padding:12px;
border-radius:10px;
color:#ff8996;
margin-bottom:15px;
}
</style>
</head>

<body>

<div class="login">

<div class="logo">MATIA // SECURITY CHECK</div>

<h1>{{ title }}</h1>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="post">

<input
type="email"
name="email"
placeholder="Email"
required
>

<input
type="password"
name="password"
placeholder="Password"
required
>

<button>AUTHENTICATE</button>

</form>

</div>

</body>
</html>
"""


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    error = None

    if request.method == "POST":

        email = request.form.get("email", "")
        password = request.form.get("password", "")

        if (
            hmac.compare_digest(email, ADMIN_EMAIL)
            and
            hmac.compare_digest(password, ADMIN_PASSWORD)
        ):
            session.clear()
            session["role"] = "admin"
            return redirect(url_for("admin"))

        error = "Invalid admin credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="ADMIN ACCESS",
        error=error
    )


@app.route("/owner/login", methods=["GET", "POST"])
def owner_login():

    error = None

    if request.method == "POST":

        email = request.form.get("email", "")
        password = request.form.get("password", "")

        if (
            hmac.compare_digest(email, OWNER_EMAIL)
            and
            hmac.compare_digest(password, OWNER_PASSWORD)
        ):
            session.clear()
            session["role"] = "owner"
            return redirect(url_for("owner"))

        error = "Invalid owner credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="OWNER ACCESS",
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ============================================================
# DASHBOARD TEMPLATE
# ============================================================

DASHBOARD = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{{ title }}</title>

<style>
*{box-sizing:border-box}

:root{
--bg:#04070a;
--panel:#0a1015;
--panel2:#0d151b;
--line:#1b302d;
--text:#eafff9;
--muted:#78908b;
--green:#54ffd0;
--green2:#20c995;
--red:#ff5d70;
--yellow:#ffd166;
--blue:#61a7ff;
}

body{
margin:0;
background:
radial-gradient(circle at 10% 0%,#00ffc40c,transparent 25%),
radial-gradient(circle at 100% 100%,#526cff10,transparent 30%),
var(--bg);
color:var(--text);
font-family:Inter,Segoe UI,Arial;
}

.layout{
display:grid;
grid-template-columns:250px 1fr;
min-height:100vh;
}

.sidebar{
border-right:1px solid var(--line);
background:#060a0e;
padding:22px;
position:sticky;
top:0;
height:100vh;
}

.brand{
color:var(--green);
font-weight:900;
letter-spacing:3px;
font-size:14px;
margin-bottom:35px;
}

.nav{
display:grid;
gap:8px;
}

.nav button,
.nav a{
border:1px solid transparent;
background:transparent;
color:#8ba39e;
padding:13px;
border-radius:12px;
text-align:left;
text-decoration:none;
cursor:pointer;
}

.nav button:hover,
.nav a:hover,
.nav .active{
background:#0e181b;
border-color:#1e3933;
color:var(--green);
}

.main{
padding:25px;
overflow:hidden;
}

.topbar{
display:flex;
align-items:center;
justify-content:space-between;
gap:15px;
margin-bottom:25px;
}

.title{
font-size:28px;
font-weight:900;
}

.live{
display:flex;
gap:10px;
align-items:center;
color:var(--green);
font-size:12px;
font-weight:900;
letter-spacing:2px;
}

.dot{
width:9px;
height:9px;
border-radius:50%;
background:var(--green);
box-shadow:0 0 15px var(--green);
}

.bell{
position:relative;
background:#0b1318;
border:1px solid var(--line);
border-radius:12px;
padding:11px 14px;
cursor:pointer;
font-size:18px;
}

.badge{
position:absolute;
top:-6px;
right:-6px;
background:var(--red);
color:white;
font-size:10px;
min-width:19px;
height:19px;
border-radius:50%;
display:grid;
place-items:center;
font-weight:900;
}

.cards{
display:grid;
grid-template-columns:repeat(5,1fr);
gap:12px;
}

.card{
background:linear-gradient(145deg,#0a1116,#081015);
border:1px solid var(--line);
border-radius:18px;
padding:18px;
}

.label{
font-size:10px;
letter-spacing:2px;
color:var(--muted);
}

.number{
font-size:31px;
font-weight:900;
margin-top:9px;
}

.green{color:var(--green)}
.red{color:var(--red)}
.yellow{color:var(--yellow)}
.blue{color:var(--blue)}

.section{
margin-top:18px;
background:#090f14;
border:1px solid var(--line);
border-radius:20px;
padding:18px;
}

.section-head{
display:flex;
justify-content:space-between;
align-items:center;
margin-bottom:15px;
}

table{
width:100%;
border-collapse:collapse;
}

th{
font-size:10px;
color:#69827d;
letter-spacing:1px;
text-align:left;
padding:12px;
border-bottom:1px solid var(--line);
}

td{
padding:13px 12px;
border-bottom:1px solid #13221f;
}

tr:hover{
background:#0d171b;
}

.pill{
display:inline-block;
padding:6px 9px;
border-radius:999px;
background:#101c20;
border:1px solid #20352f;
font-size:10px;
font-weight:900;
}

.action{
display:inline-block;
padding:8px 11px;
border-radius:9px;
background:#11221e;
color:var(--green);
border:1px solid #24463e;
text-decoration:none;
font-size:11px;
font-weight:900;
}

.notice-panel{
position:fixed;
right:20px;
top:75px;
width:340px;
max-height:500px;
overflow:auto;
background:#091015;
border:1px solid #24443b;
border-radius:18px;
padding:15px;
box-shadow:0 30px 100px #000d;
display:none;
z-index:100;
}

.notice{
padding:13px;
border-bottom:1px solid #172724;
}

.notice b{
color:var(--green);
}

.notice small{
color:#607873;
display:block;
margin-top:5px;
}

@media(max-width:1000px){
.cards{grid-template-columns:repeat(2,1fr)}
.layout{grid-template-columns:1fr}
.sidebar{height:auto;position:relative}
}

@media(max-width:600px){
.cards{grid-template-columns:1fr}
.main{padding:15px}
}
</style>
</head>

<body>

<div class="layout">

<aside class="sidebar">

<div class="brand">
MATIA // SOC
</div>

<div class="nav">

<a class="active" href="{{ dashboard_url }}">
◉ DASHBOARD
</a>

{% if role == "owner" %}
<a href="/owner">
👑 OWNER
</a>
{% endif %}

<a href="/logout">
↪ LOGOUT
</a>

</div>

<div style="position:absolute;bottom:25px;color:#536d67;font-size:11px">
VERSION {{ version }}<br>
ROLE: {{ role|upper }}<br>
SYSTEM: ONLINE
</div>

</aside>

<main class="main">

<div class="topbar">

<div>
<div class="title">
{{ title }}
</div>

<div class="live">
<span class="dot"></span>
LIVE OPERATIONS
</div>
</div>

<div class="bell" onclick="toggleNotifications()">
🔔
<span id="badge" class="badge">0</span>
</div>

</div>

<div id="noticePanel" class="notice-panel">
<div style="font-weight:900;margin-bottom:10px">
LIVE NOTIFICATIONS
</div>
<div id="notifications"></div>
</div>

<div class="cards">

<div class="card">
<div class="label">TOTAL</div>
<div id="s_total" class="number">{{ data.total }}</div>
</div>

<div class="card">
<div class="label">PENDING</div>
<div id="s_pending" class="number yellow">{{ data.PENDING }}</div>
</div>

<div class="card">
<div class="label">ACCEPTED</div>
<div id="s_accepted" class="number green">{{ data.ACCEPTED }}</div>
</div>

<div class="card">
<div class="label">ACTIVE</div>
<div id="s_active" class="number blue">{{ data['IN PROGRESS'] }}</div>
</div>

<div class="card">
<div class="label">FINDINGS</div>
<div id="s_findings" class="number red">{{ data.findings }}</div>
</div>

</div>

<div class="section">

<div class="section-head">

<h3>SECURITY REQUESTS</h3>

<div style="font-size:11px;color:#617973">
AUTO REFRESH 1s
</div>

</div>

<div style="overflow:auto">

<table>

<thead>
<tr>
<th>ID</th>
<th>CLIENT</th>
<th>TARGET</th>
<th>STATUS</th>
<th>CREATED</th>
<th></th>
</tr>
</thead>

<tbody id="clients">

{% for r in requests %}

<tr>

<td>#{{ r.id }}</td>

<td>
<strong>{{ r.name }}</strong><br>
<small style="color:#657d78">
{{ r.email }}
</small>
</td>

<td>{{ r.target }}</td>

<td>
<span class="pill">{{ r.status }}</span>
</td>

<td>{{ r.created_at }}</td>

<td>
<a
class="action"
href="{{ detail_base }}/{{ r.id }}"
>
OPEN
</a>
</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</main>

</div>

<script>

let lastNotificationId = 0;
let audioEnabled = false;
let audioContext = null;

function enableAudio(){

    if(!audioContext){

        audioContext =
            new (window.AudioContext || window.webkitAudioContext)();

    }

    audioContext.resume();
    audioEnabled = true;
}

document.addEventListener("click", enableAudio, {once:true});

function ring(){

    if(!audioEnabled || !audioContext) return;

    const osc = audioContext.createOscillator();
    const gain = audioContext.createGain();

    osc.connect(gain);
    gain.connect(audioContext.destination);

    gain.gain.value = 0.045;

    osc.frequency.value = 880;
    osc.start();

    setTimeout(() => {
        osc.frequency.value = 660;
    }, 130);

    setTimeout(() => {
        osc.stop();
    }, 260);
}

function toggleNotifications(){

    const p =
        document.getElementById("noticePanel");

    p.style.display =
        p.style.display === "block"
        ? "none"
        : "block";
}

async function poll(){

    try{

        const data =
            await fetch(
                "/api/staff/notifications",
                {cache:"no-store"}
            ).then(r => r.json());

        const badge =
            document.getElementById("badge");

        badge.textContent =
            data.unread > 99
            ? "99+"
            : data.unread;

        const box =
            document.getElementById("notifications");

        box.innerHTML = "";

        for(const n of data.items){

            const div =
                document.createElement("div");

            div.className = "notice";

            div.innerHTML =
                "<b>" +
                escapeHtml(n.title) +
                "</b>" +
                "<div>" +
                escapeHtml(n.body) +
                "</div>" +
                "<small>" +
                escapeHtml(n.created_at) +
                "</small>";

            box.appendChild(div);
        }

        if(
            lastNotificationId &&
            data.latest_id > lastNotificationId
        ){
            ring();
        }

        lastNotificationId =
            data.latest_id || lastNotificationId;

        if(data.stats){

            document.getElementById("s_total").textContent =
                data.stats.total;

            document.getElementById("s_pending").textContent =
                data.stats.PENDING;

            document.getElementById("s_accepted").textContent =
                data.stats.ACCEPTED;

            document.getElementById("s_active").textContent =
                data.stats["IN PROGRESS"];

            document.getElementById("s_findings").textContent =
                data.stats.findings;
        }

    }catch(e){}
}

function escapeHtml(value){

    const div =
        document.createElement("div");

    div.textContent = value ?? "";

    return div.innerHTML;
}

poll();
setInterval(poll,1000);

</script>

</body>
</html>
"""


def render_dashboard(role):

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    conn.close()

    return render_template_string(
        DASHBOARD,
        title=(
            "OWNER COMMAND CENTER"
            if role == "owner"
            else "ADMIN SECURITY CENTER"
        ),
        role=role,
        version=VERSION,
        data=stats(),
        requests=rows,
        dashboard_url=(
            "/owner"
            if role == "owner"
            else "/admin"
        ),
        detail_base=(
            "/admin/client"
        )
    )


@app.route("/admin")
@role_required("admin")
def admin():

    return render_dashboard("admin")


@app.route("/owner")
@role_required("owner")
def owner():

    return render_dashboard("owner")


# ============================================================
# STAFF NOTIFICATIONS
# ============================================================

@app.route("/api/staff/notifications")
@staff_required
def staff_notifications():

    conn = db()

    rows = conn.execute(
        """
        SELECT id, request_id, kind, title, body, created_at, read
        FROM notifications
        WHERE audience='staff'
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    unread = conn.execute(
        """
        SELECT COUNT(*) c
        FROM notifications
        WHERE audience='staff' AND read=0
        """
    ).fetchone()["c"]

    conn.close()

    return jsonify({
        "unread": unread,
        "latest_id": rows[0]["id"] if rows else 0,
        "items": [dict(x) for x in rows],
        "stats": stats()
    })


@app.route("/api/staff/notifications/read", methods=["POST"])
@staff_required
def mark_notifications_read():

    conn = db()

    conn.execute(
        """
        UPDATE notifications
        SET read=1
        WHERE audience='staff'
        """
    )

    conn.commit()
    conn.close()

    return jsonify({"ok": True})


# ============================================================
# STAFF CLIENT DETAIL
# ============================================================

STAFF_DETAIL = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">

<title>Client #{{ row.id }}</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
background:
radial-gradient(circle at 10% 0%,#00ffc410,transparent 25%),
#04070a;
color:#eafff9;
font-family:Inter,Segoe UI,Arial;
}

.wrap{
max-width:1450px;
margin:auto;
padding:22px;
}

.top{
display:flex;
justify-content:space-between;
align-items:center;
gap:15px;
flex-wrap:wrap;
}

.logo{
color:#5fffd0;
font-weight:900;
letter-spacing:4px;
}

.back{
color:#78928c;
text-decoration:none;
}

.grid{
display:grid;
grid-template-columns:380px 1fr 380px;
gap:15px;
margin-top:20px;
}

.panel{
background:#090f14;
border:1px solid #1b302d;
border-radius:20px;
padding:18px;
box-shadow:0 15px 60px #0008;
}

.info{
display:grid;
gap:10px;
}

.info div{
background:#070d11;
border:1px solid #172723;
padding:12px;
border-radius:11px;
}

.label{
font-size:9px;
letter-spacing:2px;
color:#617a75;
display:block;
margin-bottom:5px;
}

.chat{
height:690px;
display:flex;
flex-direction:column;
}

.messages{
flex:1;
overflow:auto;
padding:10px;
}

.msg{
max-width:80%;
padding:12px 14px;
margin:8px 0;
background:#101a20;
border:1px solid #20342f;
border-radius:14px;
}

.msg.staff{
margin-left:auto;
background:#13382f;
}

.msg.system{
margin-left:auto;
margin-right:auto;
background:#111719;
color:#77918c;
text-align:center;
font-size:12px;
}

.time{
font-size:9px;
color:#5e7772;
margin-top:6px;
}

.compose{
display:flex;
gap:8px;
padding-top:12px;
}

.compose input{
flex:1;
background:#05090d;
border:1px solid #1c3430;
border-radius:11px;
padding:13px;
color:white;
}

button{
border:1px solid #24473e;
background:#10251f;
color:#65ffd1;
border-radius:10px;
padding:10px 13px;
font-weight:900;
cursor:pointer;
}

button:hover{
background:#15372e;
}

.danger{
color:#ff7180;
border-color:#51232b;
background:#241015;
}

.warn{
color:#ffd166;
}

.actiongrid{
display:grid;
grid-template-columns:1fr 1fr;
gap:8px;
margin-top:15px;
}

textarea{
width:100%;
min-height:90px;
background:#05090d;
border:1px solid #1c3430;
border-radius:11px;
padding:12px;
color:white;
resize:vertical;
}

select{
width:100%;
padding:11px;
background:#05090d;
border:1px solid #1c3430;
border-radius:10px;
color:white;
}

.live{
color:#5fffd0;
font-size:11px;
font-weight:900;
letter-spacing:2px;
}

@media(max-width:1200px){
.grid{grid-template-columns:1fr 1fr}
}

@media(max-width:800px){
.grid{grid-template-columns:1fr}
.chat{height:550px}
}
</style>
</head>

<body>

<div class="wrap">

<div class="top">

<div>
<div class="logo">MATIA // SECURITY CHECK</div>
<div style="margin-top:8px">
CLIENT #{{ row.id }}
</div>
</div>

<a class="back"
href="{{ '/owner' if role == 'owner' else '/admin' }}">
← BACK TO COMMAND CENTER
</a>

</div>

<div class="grid">

<!-- LEFT -->

<div class="panel">

<h3>CLIENT INTEL</h3>

<div class="info">

<div>
<span class="label">NAME</span>
{{ row.name }}
</div>

<div>
<span class="label">EMAIL</span>
{{ row.email }}
</div>

<div>
<span class="label">PROJECT</span>
{{ row.web_name }}
</div>

<div>
<span class="label">TARGET</span>
{{ row.target }}
</div>

<div>
<span class="label">STATUS</span>
<b id="status">{{ row.status }}</b>
</div>

<div>
<span class="label">SCOPE</span>
{{ row.scope }}
</div>

</div>

<h3 style="margin-top:25px">LIFECYCLE</h3>

<div class="actiongrid">

<button onclick="setStatus('ACCEPTED')">
ACCEPT
</button>

<button onclick="setStatus('IN PROGRESS')">
START
</button>

<button
class="danger"
onclick="setStatus('DECLINED')">
DECLINE
</button>

<button onclick="setStatus('PENDING')">
REOPEN
</button>

<button onclick="setStatus('COMPLETED')">
COMPLETE
</button>

</div>

</div>

<!-- CHAT -->

<div class="panel chat">

<div style="display:flex;justify-content:space-between">

<h3>LIVE CLIENT CHANNEL</h3>

<div class="live">
● LIVE
</div>

</div>

<div id="messages" class="messages"></div>

<div class="compose">

<input
id="message"
placeholder="Message client..."
>

<button onclick="sendMessage()">
SEND
</button>

</div>

</div>

<!-- RIGHT -->

<div>

<div class="panel">

<h3>PUBLISH FINDING</h3>

<input
id="findingTitle"
placeholder="Finding title"
style="width:100%;padding:12px;background:#05090d;border:1px solid #1c3430;border-radius:10px;color:white"
>

<br><br>

<select id="findingSeverity">

<option>INFO</option>
<option>LOW</option>
<option>MEDIUM</option>
<option>HIGH</option>
<option>CRITICAL</option>

</select>

<br><br>

<textarea
id="findingDescription"
placeholder="Description"
></textarea>

<br>

<textarea
id="findingEvidence"
placeholder="Evidence"
></textarea>

<br>

<textarea
id="findingRecommendation"
placeholder="Recommendation"
></textarea>

<button
style="width:100%;margin-top:8px"
onclick="publishFinding()">
PUBLISH FINDING
</button>

</div>

<div class="panel" style="margin-top:15px">

<h3>ACTIVITY</h3>

<div id="activity">
Loading...
</div>

</div>

</div>

</div>

</div>

<script>

const requestId = {{ row.id }};

let lastMessageId = 0;

function esc(value){

    const div =
        document.createElement("div");

    div.textContent = value ?? "";

    return div.innerHTML;
}

async function load(){

    try{

        const data =
            await fetch(
                `/api/staff/client/${requestId}/data`,
                {cache:"no-store"}
            ).then(r => r.json());

        document.getElementById("status")
            .textContent =
            data.request.status;

        const box =
            document.getElementById("messages");

        const shouldScroll =
            box.scrollHeight -
            box.scrollTop -
            box.clientHeight < 120;

        box.innerHTML = "";

        for(const m of data.messages){

            const div =
                document.createElement("div");

            let cls = "msg";

            if(m.sender === "SYSTEM")
                cls += " system";
            else if(
                m.sender === "ADMIN" ||
                m.sender === "OWNER"
            )
                cls += " staff";

            div.className = cls;

            div.innerHTML =
                "<div>" +
                esc(m.message) +
                "</div>" +
                "<div class='time'>" +
                esc(m.sender) +
                " • " +
                esc(m.created_at) +
                "</div>";

            box.appendChild(div);
        }

        if(shouldScroll)
            box.scrollTop = box.scrollHeight;

        lastMessageId =
            data.messages.length
            ? data.messages[data.messages.length - 1].id
            : lastMessageId;

        let html = "";

        for(const f of data.findings){

            html += `
            <div style="
                padding:10px;
                border-bottom:1px solid #172724
            ">
                <b>${esc(f.title)}</b>
                <br>
                <small>${esc(f.severity)}</small>
                <br>
                <small style="color:#6f8882">
                ${esc(f.created_at)}
                </small>
            </div>
            `;
        }

        document.getElementById("activity").innerHTML =
            html || "No findings yet.";

    }catch(e){}
}

async function sendMessage(){

    const input =
        document.getElementById("message");

    const message =
        input.value.trim();

    if(!message) return;

    input.disabled = true;

    try{

        const res =
            await fetch(
                `/api/staff/client/${requestId}/message`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify({
                        message
                    })
                }
            );

        if(res.ok){
            input.value = "";
            await load();
        }

    }finally{
        input.disabled = false;
        input.focus();
    }
}

async function setStatus(status){

    const res =
        await fetch(
            `/api/staff/client/${requestId}/status`,
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({status})
            }
        );

    if(res.ok){
        await load();
    }else{
        const data = await res.json().catch(() => ({}));
        alert(data.error || "Status update failed.");
    }
}

async function publishFinding(){

    const payload = {

        title:
            document.getElementById(
                "findingTitle"
            ).value.trim(),

        severity:
            document.getElementById(
                "findingSeverity"
            ).value,

        description:
            document.getElementById(
                "findingDescription"
            ).value.trim(),

        evidence:
            document.getElementById(
                "findingEvidence"
            ).value.trim(),

        recommendation:
            document.getElementById(
                "findingRecommendation"
            ).value.trim()
    };

    if(!payload.title || !payload.description){

        alert("Title and description are required.");

        return;
    }

    const res =
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

    if(res.ok){

        document.getElementById("findingTitle").value = "";
        document.getElementById("findingDescription").value = "";
        document.getElementById("findingEvidence").value = "";
        document.getElementById("findingRecommendation").value = "";

        await load();

    }else{

        alert("Could not publish finding.");
    }
}

document
.getElementById("message")
.addEventListener("keydown", e => {

    if(e.key === "Enter"){
        e.preventDefault();
        sendMessage();
    }

});

load();

setInterval(load,1000);

</script>

</body>
</html>
"""


@app.route("/admin/client/<int:request_id>")
@staff_required
def staff_client(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    return render_template_string(
        STAFF_DETAIL,
        row=row,
        role=current_role()
    )


# ============================================================
# STAFF LIVE API
# ============================================================

@app.route(
    "/api/staff/client/<int:request_id>/data"
)
@staff_required
def staff_client_data(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    conn = db()

    messages = conn.execute(
        """
        SELECT id, sender, message, created_at
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    return jsonify({
        "request": dict(row),
        "messages": [dict(x) for x in messages],
        "findings": [dict(x) for x in findings]
    })


@app.route(
    "/api/staff/client/<int:request_id>/status",
    methods=["POST"]
)
@staff_required
def staff_client_status(request_id):

    data = request.get_json(silent=True) or {}

    status = clean_text(
        data.get("status"),
        50
    )

    if status not in STATUS_ORDER:
        return jsonify({
            "ok": False,
            "error": "Invalid status."
        }), 400

    ok, message = set_status(
        request_id,
        status,
        current_role().upper()
    )

    if not ok:
        return jsonify({
            "ok": False,
            "error": message
        }), 400

    return jsonify({
        "ok": True,
        "status": status
    })


@app.route(
    "/api/staff/client/<int:request_id>/message",
    methods=["POST"]
)
@staff_required
def staff_client_message(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    if row["status"] not in OPEN_CHAT_STATUSES:
        return jsonify({
            "ok": False,
            "error": "Chat is not open."
        }), 400

    data = request.get_json(silent=True) or {}

    message = clean_text(
        data.get("message"),
        2000
    )

    if not message:
        return jsonify({
            "ok": False,
            "error": "Empty message."
        }), 400

    sender = current_role().upper()

    add_message(
        request_id,
        sender,
        message
    )

    notify_client(
        request_id,
        "message",
        "NEW SECURITY MESSAGE",
        f"{sender}: {message[:160]}"
    )

    audit_action(
        sender,
        "SENT CLIENT MESSAGE",
        request_id
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# FINDINGS
# ============================================================

@app.route(
    "/staff/client/<int:request_id>/finding",
    methods=["POST"]
)
@staff_required
def create_finding(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    data = request.get_json(silent=True)

    if not data:
        data = request.form

    title = clean_text(
        data.get("title"),
        200
    )

    severity = clean_text(
        data.get("severity"),
        20
    ).upper()

    description = clean_text(
        data.get("description"),
        5000
    )

    evidence = clean_text(
        data.get("evidence"),
        5000
    )

    recommendation = clean_text(
        data.get("recommendation"),
        5000
    )

    if not title or not description:
        return jsonify({
            "ok": False,
            "error": "Title and description required."
        }), 400

    if severity not in SEVERITIES:
        return jsonify({
            "ok": False,
            "error": "Invalid severity."
        }), 400

    conn = db()

    cur = conn.execute(
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
            now()
        )
    )

    finding_id = cur.lastrowid

    conn.commit()
    conn.close()

    system_message(
        request_id,
        f"New finding published: {title} [{severity}]"
    )

    notify_client(
        request_id,
        "finding",
        "NEW SECURITY FINDING",
        f"{title} [{severity}]"
    )

    audit_action(
        current_role().upper(),
        f"CREATED FINDING #{finding_id}",
        request_id
    )

    return jsonify({
        "ok": True,
        "finding_id": finding_id
    })


# ============================================================
# REPORT
# ============================================================

@app.route("/staff/client/<int:request_id>/report")
@staff_required
def staff_report(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    conn = db()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    return render_template_string("""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Report #{{ row.id }}</title>

<style>
body{
background:#05070b;
color:#eafff9;
font-family:Arial;
padding:40px;
}

.report{
max-width:900px;
margin:auto;
background:#0a1116;
border:1px solid #20352f;
padding:35px;
border-radius:20px;
}

.finding{
padding:20px;
margin-top:15px;
border:1px solid #20352f;
border-radius:15px;
}

h1,h2{
color:#62ffd0;
}

small{
color:#6e8983;
}
</style>
</head>

<body>

<div class="report">

<h1>MATIA // SECURITY CHECK</h1>

<h2>Security Assessment Report #{{ row.id }}</h2>

<p>
<b>Client:</b> {{ row.name }}
</p>

<p>
<b>Project:</b> {{ row.web_name }}
</p>

<p>
<b>Target:</b> {{ row.target }}
</p>

<p>
<b>Status:</b> {{ row.status }}
</p>

<hr>

<h2>Findings</h2>

{% if findings %}

{% for f in findings %}

<div class="finding">

<h3>{{ f.title }}</h3>

<small>
Severity: {{ f.severity }} • {{ f.created_at }}
</small>

<p>
{{ f.description }}
</p>

{% if f.evidence %}
<p>
<b>Evidence</b><br>
{{ f.evidence }}
</p>
{% endif %}

{% if f.recommendation %}
<p>
<b>Recommendation</b><br>
{{ f.recommendation }}
</p>
{% endif %}

</div>

{% endfor %}

{% else %}

<p>No findings published.</p>

{% endif %}

</div>

</body>
</html>
""", row=row, findings=findings)


# ============================================================
# OWNER TERMINAL
# ============================================================

OWNER_TERMINAL = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Owner Terminal</title>

<style>
*{box-sizing:border-box}

body{
margin:0;
background:#020403;
color:#6dffd0;
font-family:
"Courier New",
Consolas,
monospace;
}

.terminal{
min-height:100vh;
padding:25px;
}

.header{
display:flex;
justify-content:space-between;
padding:15px;
border:1px solid #164337;
background:#06100d;
border-radius:12px 12px 0 0;
}

.title{
font-weight:900;
letter-spacing:3px;
}

.back{
color:#67cdb1;
text-decoration:none;
}

.screen{
min-height:calc(100vh - 130px);
border:1px solid #164337;
border-top:0;
background:
radial-gradient(circle at 50% 0%,#00ff9d09,transparent 40%),
#020403;
padding:20px;
overflow:auto;
}

.line{
margin:5px 0;
white-space:pre-wrap;
}

.cmd{
color:#eafff9;
}

.inputline{
display:flex;
gap:8px;
margin-top:12px;
}

.prompt{
color:#41ffc1;
}

input{
flex:1;
background:transparent;
border:0;
outline:none;
color:#eafff9;
font-family:inherit;
font-size:15px;
}

.cursor{
animation:blink 1s infinite;
}

@keyframes blink{
50%{opacity:0}
}
</style>
</head>

<body>

<div class="terminal">

<div class="header">

<div class="title">
MATIA // OWNER TERMINAL
</div>

<a class="back" href="/owner">
← DASHBOARD
</a>

</div>

<div class="screen" id="screen">

<div class="line">
MATIA SECURITY CHECK OWNER SHELL {{ version }}
</div>

<div class="line">
AUTHORIZED APPLICATION ADMINISTRATION CONSOLE
</div>

<div class="line">
Type <span class="cmd">help</span> to list commands.
</div>

<div id="output"></div>

<div class="inputline">

<span class="prompt">
owner@matia:~$
</span>

<input
id="command"
autocomplete="off"
autofocus
>

</div>

</div>

</div>

<script>

const input =
document.getElementById("command");

const output =
document.getElementById("output");

function print(text){

    const div =
        document.createElement("div");

    div.className = "line";

    div.textContent = text;

    output.appendChild(div);

    window.scrollTo(
        0,
        document.body.scrollHeight
    );
}

async function runCommand(){

    const command =
        input.value.trim();

    if(!command) return;

    print(
        "owner@matia:~$ " + command
    );

    input.value = "";

    try{

        const res =
            await fetch(
                "/owner/command",
                {
                    method:"POST",
                    headers:{
                        "Content-Type":"application/json"
                    },
                    body:JSON.stringify({
                        command
                    })
                }
            );

        const data =
            await res.json();

        if(data.output){

            for(const line of data.output.split("\\n")){
                print(line);
            }

        }

    }catch(e){

        print("ERROR: terminal connection failed.");

    }
}

input.addEventListener(
    "keydown",
    e => {

        if(e.key === "Enter"){
            runCommand();
        }

    }
);

</script>

</body>
</html>
"""


# ============================================================
# OWNER COMMAND ENGINE
# ============================================================

COMMAND_HELP = {
    "help": "Show command list",
    "clear": "Clear terminal",
    "status": "System status",
    "stats": "Application statistics",
    "clients": "List latest clients",
    "pending": "List pending requests",
    "accepted": "List accepted requests",
    "active": "List active requests",
    "completed": "List completed requests",
    "declined": "List declined requests",
    "client <id>": "Show client",
    "status <id>": "Show client status",
    "accept <id>": "Accept request",
    "decline <id>": "Decline request",
    "start <id>": "Start request",
    "complete <id>": "Complete request",
    "reopen <id>": "Reopen request",
    "message <id> <text>": "Send client message",
    "findings <id>": "Show client findings",
    "findings-total": "Total findings",
    "report <id>": "Report information",
    "notify <text>": "Create staff notification",
    "announce <text>": "Broadcast staff announcement",
    "audit": "Show recent audit events",
    "version": "Show application version",
    "time": "Show server time",
    "db": "Show database information",
    "requests-count": "Show request count",
    "messages-count": "Show message count",
    "notifications-count": "Show notification count",
    "findings-count": "Show finding count",
    "critical": "Show critical findings",
    "high": "Show high findings",
    "medium": "Show medium findings",
    "low": "Show low findings",
    "info": "Show informational findings",
    "whoami": "Show current role",
    "ping": "Application health check",
    "online": "Show online state",
    "maintenance": "Show maintenance information",
}


def command_output_list(rows):

    if not rows:
        return "No results."

    lines = []

    for r in rows:

        lines.append(
            f"#{r['id']} | "
            f"{r['name']} | "
            f"{r['status']} | "
            f"{r['target']}"
        )

    return "\n".join(lines)


def execute_command(command):

    command = command.strip()

    if not command:
        return ""

    parts = command.split()
    cmd = parts[0].lower()
    args = parts[1:]

    # --------------------------------------------------------
    # BASIC
    # --------------------------------------------------------

    if cmd == "help":

        lines = [
            "==============================================",
            " MATIA // OWNER COMMAND CENTER",
            "==============================================",
        ]

        for key, description in COMMAND_HELP.items():
            lines.append(
                f"{key:<32} {description}"
            )

        lines.extend([
            "",
            "All commands operate on this application.",
            "No operating-system shell is exposed."
        ])

        return "\n".join(lines)

    if cmd == "clear":
        return "CLEAR"

    if cmd == "version":
        return VERSION

    if cmd == "time":
        return now()

    if cmd == "whoami":
        return "OWNER"

    if cmd in {"ping", "online"}:
        return "PONG // MATIA SECURITY CHECK ONLINE"

    # --------------------------------------------------------
    # STATS
    # --------------------------------------------------------

    if cmd == "stats":

        s = stats()

        return "\n".join([
            f"TOTAL       : {s['total']}",
            f"PENDING     : {s[PENDING]}",
            f"ACCEPTED    : {s[ACCEPTED]}",
            f"IN PROGRESS : {s[IN_PROGRESS]}",
            f"COMPLETED   : {s[COMPLETED]}",
            f"DECLINED    : {s[DECLINED]}",
            f"FINDINGS    : {s['findings']}",
        ])

    # --------------------------------------------------------
    # CLIENT LISTS
    # --------------------------------------------------------

    status_alias = {
        "pending": PENDING,
        "accepted": ACCEPTED,
        "active": IN_PROGRESS,
        "completed": COMPLETED,
        "declined": DECLINED,
    }

    if cmd == "clients" or cmd in status_alias:

        conn = db()

        if cmd == "clients":

            rows = conn.execute(
                """
                SELECT *
                FROM requests
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()

        else:

            rows = conn.execute(
                """
                SELECT *
                FROM requests
                WHERE status=?
                ORDER BY id DESC
                LIMIT 50
                """,
                (status_alias[cmd],)
            ).fetchall()

        conn.close()

        return command_output_list(rows)

    # --------------------------------------------------------
    # CLIENT
    # --------------------------------------------------------

    if cmd in {
        "client",
        "status",
        "accept",
        "decline",
        "start",
        "complete",
        "reopen",
        "findings",
        "report",
    }:

        if not args:
            return "Usage: " + cmd + " <id>"

        request_id = safe_int(args[0], -1)

        if request_id < 1:
            return "Invalid client ID."

        row = get_request(request_id)

        if not row:
            return "Client not found."

        if cmd == "client":

            return "\n".join([
                f"ID       : {row['id']}",
                f"NAME     : {row['name']}",
                f"EMAIL    : {row['email']}",
                f"PROJECT  : {row['web_name']}",
                f"TARGET   : {row['target']}",
                f"STATUS   : {row['status']}",
                f"CREATED  : {row['created_at']}",
                f"UPDATED  : {row['updated_at']}",
                f"SCOPE    : {row['scope']}",
            ])

        if cmd == "status":

            return (
                f"Client #{request_id}: "
                f"{row['status']}"
            )

        transitions = {
            "accept": ACCEPTED,
            "decline": DECLINED,
            "start": IN_PROGRESS,
            "complete": COMPLETED,
            "reopen": PENDING,
        }

        if cmd in transitions:

            ok, message = set_status(
                request_id,
                transitions[cmd],
                "OWNER"
            )

            return message

        if cmd == "findings":

            conn = db()

            findings = conn.execute(
                """
                SELECT *
                FROM findings
                WHERE request_id=?
                ORDER BY id DESC
                """,
                (request_id,)
            ).fetchall()

            conn.close()

            if not findings:
                return "No findings."

            return "\n".join(
                f"#{f['id']} | "
                f"{f['severity']} | "
                f"{f['title']}"
                for f in findings
            )

        if cmd == "report":

            conn = db()

            count = conn.execute(
                """
                SELECT COUNT(*) c
                FROM findings
                WHERE request_id=?
                """,
                (request_id,)
            ).fetchone()["c"]

            conn.close()

            return (
                f"REPORT #{request_id}\n"
                f"Client: {row['name']}\n"
                f"Target: {row['target']}\n"
                f"Status: {row['status']}\n"
                f"Findings: {count}"
            )

    # --------------------------------------------------------
    # MESSAGE
    # --------------------------------------------------------

    if cmd == "message":

        if len(args) < 2:
            return "Usage: message <id> <text>"

        request_id = safe_int(args[0], -1)

        row = get_request(request_id)

        if not row:
            return "Client not found."

        message = " ".join(args[1:])

        if row["status"] not in OPEN_CHAT_STATUSES:
            return "Chat is not open."

        add_message(
            request_id,
            "OWNER",
            message
        )

        notify_client(
            request_id,
            "message",
            "OWNER MESSAGE",
            message[:200]
        )

        audit_action(
            "OWNER",
            "TERMINAL MESSAGE",
            request_id
        )

        return "Message sent."

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    if cmd in {"notify", "announce"}:

        if not args:
            return f"Usage: {cmd} <text>"

        text_value = " ".join(args)

        notify_staff(
            "announcement",
            "OWNER ANNOUNCEMENT",
            text_value
        )

        return "Notification created."

    # --------------------------------------------------------
    # FINDING COUNTS
    # --------------------------------------------------------

    if cmd in {
        "findings-total",
        "findings-count",
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }:

        conn = db()

        if cmd in {"findings-total", "findings-count"}:

            count = conn.execute(
                "SELECT COUNT(*) c FROM findings"
            ).fetchone()["c"]

            conn.close()

            return f"TOTAL FINDINGS: {count}"

        severity = cmd.upper()

        count = conn.execute(
            """
            SELECT COUNT(*) c
            FROM findings
            WHERE severity=?
            """,
            (severity,)
        ).fetchone()["c"]

        conn.close()

        return f"{severity}: {count}"

    # --------------------------------------------------------
    # COUNTS
    # --------------------------------------------------------

    if cmd == "requests-count":

        conn = db()

        count = conn.execute(
            "SELECT COUNT(*) c FROM requests"
        ).fetchone()["c"]

        conn.close()

        return f"REQUESTS: {count}"

    if cmd == "messages-count":

        conn = db()

        count = conn.execute(
            "SELECT COUNT(*) c FROM messages"
        ).fetchone()["c"]

        conn.close()

        return f"MESSAGES: {count}"

    if cmd == "notifications-count":

        conn = db()

        count = conn.execute(
            "SELECT COUNT(*) c FROM notifications"
        ).fetchone()["c"]

        conn.close()

        return f"NOTIFICATIONS: {count}"

    # --------------------------------------------------------
    # AUDIT
    # --------------------------------------------------------

    if cmd == "audit":

        conn = db()

        rows = conn.execute(
            """
            SELECT *
            FROM audit_log
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

        conn.close()

        if not rows:
            return "No audit events."

        return "\n".join(
            f"#{r['id']} | "
            f"{r['created_at']} | "
            f"{r['actor']} | "
            f"{r['action']}"
            for r in rows
        )

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    if cmd == "db":

        try:
            size = os.path.getsize(DB_PATH)
        except Exception:
            size = 0

        return "\n".join([
            "DATABASE STATUS",
            f"PATH: {DB_PATH}",
            f"SIZE: {size} bytes",
            "ENGINE: SQLite",
            "MODE: WAL",
            "STATUS: ONLINE",
        ])

    if cmd == "maintenance":

        return "\n".join([
            "MAINTENANCE",
            "Application: ONLINE",
            "Database: ONLINE",
            "Live API: ONLINE",
            "Chat: ONLINE",
            "Notifications: ONLINE",
            "OS shell: DISABLED",
        ])

    return (
        f"Unknown command: {cmd}\n"
        "Type 'help' to list available commands."
    )


@app.route("/owner/terminal")
@role_required("owner")
def owner_terminal():

    return render_template_string(
        OWNER_TERMINAL,
        version=VERSION
    )


@app.route("/owner/command", methods=["POST"])
@role_required("owner")
def owner_command():

    data = request.get_json(silent=True) or {}

    command = clean_text(
        data.get("command"),
        2000
    )

    if not command:
        return jsonify({
            "ok": False,
            "output": ""
        })

    output = execute_command(command)

    if output == "CLEAR":

        return jsonify({
            "ok": True,
            "clear": True,
            "output": ""
        })

    audit_action(
        "OWNER",
        f"COMMAND {command[:200]}"
    )

    return jsonify({
        "ok": True,
        "output": output
    })


# ============================================================
# OWNER DASHBOARD TERMINAL LINK
# ============================================================

@app.context_processor
def inject_owner_terminal():

    return {
        "owner_terminal_url":
            "/owner/terminal"
    }


# ============================================================
# ERROR PAGES
# ============================================================

@app.errorhandler(403)
def forbidden(error):

    return """
    <body style="
        background:#05070b;
        color:#ff6b7a;
        font-family:monospace;
        padding:50px">
        <h1>403 // ACCESS DENIED</h1>
        <p>You do not have permission to access this resource.</p>
    </body>
    """, 403


@app.errorhandler(404)
def not_found(error):

    return """
    <body style="
        background:#05070b;
        color:#63ffd0;
        font-family:monospace;
        padding:50px">
        <h1>404 // NOT FOUND</h1>
    </body>
    """, 404


# ============================================================
# HEALTH
# ============================================================

@app.route("/healthz")
def healthz():

    return jsonify({
        "status": "ok",
        "app": APP_NAME,
        "version": VERSION,
        "time": now()
    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
