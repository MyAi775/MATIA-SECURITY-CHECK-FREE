import os
import re
import hmac
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
# SOC EDITION
# ============================================================

APP_NAME = "MATIA // SECURITY CHECK"
VERSION = "5.0-SOC"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "MATIA_DB_PATH",
    os.path.join(BASE_DIR, "matia_security.db")
)

SECRET_KEY = os.environ.get("MATIA_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

OWNER_EMAIL = os.environ.get(
    "MATIA_OWNER_EMAIL",
    "owner@example.com"
)

OWNER_PASSWORD = os.environ.get(
    "MATIA_OWNER_PASSWORD",
    "CHANGE_ME"
)

ADMIN_EMAIL = os.environ.get(
    "MATIA_ADMIN_EMAIL",
    "admin@example.com"
)

ADMIN_PASSWORD = os.environ.get(
    "MATIA_ADMIN_PASSWORD",
    "CHANGE_ME"
)


app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    MAX_CONTENT_LENGTH=1024 * 1024,
)


# ============================================================
# STATUSES
# ============================================================

PENDING = "PENDING"
ACCEPTED = "ACCEPTED"
DECLINED = "DECLINED"
IN_PROGRESS = "IN PROGRESS"
COMPLETED = "COMPLETED"

STATUS_ORDER = [
    PENDING,
    ACCEPTED,
    IN_PROGRESS,
    COMPLETED,
    DECLINED,
]

OPEN_CHAT_STATUSES = {
    ACCEPTED,
    IN_PROGRESS,
    COMPLETED,
}

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


# ============================================================
# DATABASE
# ============================================================

def db():

    conn = sqlite3.connect(
        DB_PATH,
        timeout=15
    )

    conn.row_factory = sqlite3.Row

    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
    except Exception:
        pass

    return conn


def now():

    return datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


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
        CREATE INDEX IF NOT EXISTS idx_findings_request
        ON findings(request_id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_staff
        ON notifications(audience, read, id)
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def clean_text(value, max_len=4000):

    if value is None:
        return ""

    value = str(value).strip()

    return value[:max_len]


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


def safe_int(value, default=-1):

    try:
        return int(value)
    except Exception:
        return default


def current_role():

    return session.get("role")


def login_redirect():

    next_url = request.full_path

    return redirect(
        url_for(
            "admin_login",
            next=next_url
        )
    )


def staff_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        role = session.get("role")

        if role not in (
            "admin",
            "owner"
        ):
            return login_redirect()

        return fn(*args, **kwargs)

    return wrapper


def owner_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if session.get("role") != "owner":
            return redirect(
                url_for(
                    "owner_login",
                    next=request.full_path
                )
            )

        return fn(*args, **kwargs)

    return wrapper


def get_request(request_id):

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (request_id,)
    ).fetchone()

    conn.close()

    return row


def get_request_by_token(
    request_id,
    token
):

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        AND client_token=?
        """,
        (
            request_id,
            token
        )
    ).fetchone()

    conn.close()

    return row


# ============================================================
# NOTIFICATIONS
# ============================================================

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
        (
            request_id,
            audience,
            kind,
            title,
            body,
            created_at,
            read
        )
        VALUES (?, ?, ?, ?, ?, ?, 0)
        """,
        (
            request_id,
            audience,
            kind,
            title,
            body,
            now()
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


# ============================================================
# MESSAGES
# ============================================================

def add_message(
    request_id,
    sender,
    message
):

    conn = db()

    conn.execute(
        """
        INSERT INTO messages
        (
            request_id,
            sender,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            sender,
            message,
            now()
        )
    )

    conn.commit()
    conn.close()


def system_message(
    request_id,
    message
):

    add_message(
        request_id,
        "SYSTEM",
        message
    )


# ============================================================
# AUDIT
# ============================================================

def audit_action(
    actor,
    action,
    request_id=None
):

    conn = db()

    conn.execute(
        """
        INSERT INTO audit_log
        (
            actor,
            action,
            request_id,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            actor,
            action,
            request_id,
            now()
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# STATS
# ============================================================

def stats():

    conn = db()

    result = {
        "total": 0,
        "PENDING": 0,
        "ACCEPTED": 0,
        "IN PROGRESS": 0,
        "COMPLETED": 0,
        "DECLINED": 0,
        "findings": 0,
    }

    result["total"] = conn.execute(
        "SELECT COUNT(*) c FROM requests"
    ).fetchone()["c"]

    for status in STATUS_ORDER:

        result[status] = conn.execute(
            """
            SELECT COUNT(*) c
            FROM requests
            WHERE status=?
            """,
            (status,)
        ).fetchone()["c"]

    result["findings"] = conn.execute(
        "SELECT COUNT(*) c FROM findings"
    ).fetchone()["c"]

    conn.close()

    return result


# ============================================================
# STATUS ENGINE
# ============================================================

def set_status(
    request_id,
    new_status,
    actor
):

    row = get_request(request_id)

    if not row:
        return False, "Client not found."

    old_status = row["status"]

    allowed = {

        PENDING: {
            ACCEPTED,
            DECLINED
        },

        ACCEPTED: {
            IN_PROGRESS,
            DECLINED
        },

        IN_PROGRESS: {
            COMPLETED,
            ACCEPTED
        },

        COMPLETED: {
            IN_PROGRESS
        },

        DECLINED: {
            PENDING,
            ACCEPTED
        },
    }

    if new_status not in allowed.get(
        old_status,
        set()
    ):

        return False, (
            f"Cannot change "
            f"{old_status} -> {new_status}"
        )

    conn = db()

    conn.execute(
        """
        UPDATE requests
        SET status=?,
            updated_at=?
        WHERE id=?
        """,
        (
            new_status,
            now(),
            request_id
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
        f"{actor} changed status to {new_status}."
    )

    notify_client(
        request_id,
        "status",
        f"REQUEST {new_status}",
        f"Your request is now {new_status}."
    )

    notify_staff(
        "status",
        f"REQUEST #{request_id}",
        f"{actor} changed status to {new_status}.",
        request_id
    )

    return True, "Status updated."


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

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

*{
box-sizing:border-box;
}

body{
margin:0;
min-height:100vh;
background:
radial-gradient(
circle at 20% 20%,
rgba(0,255,190,.10),
transparent 30%
),
radial-gradient(
circle at 80% 80%,
rgba(80,80,255,.10),
transparent 30%
),
#040608;

color:#ecfffa;

font-family:
Inter,
Segoe UI,
Arial;
}

.wrap{
max-width:1200px;
margin:auto;
padding:80px 25px;
}

.logo{
font-weight:900;
letter-spacing:5px;
color:#5fffd0;
}

h1{
font-size:64px;
line-height:1;
margin:25px 0;
}

p{
color:#8ca49f;
font-size:18px;
line-height:1.7;
}

.actions{
display:flex;
gap:12px;
flex-wrap:wrap;
margin-top:35px;
}

a{
text-decoration:none;
color:white;
padding:15px 22px;
border-radius:13px;
background:#0d151a;
border:1px solid #203530;
}

.primary{
background:#35dca4;
color:#04100c;
font-weight:900;
}

.grid{
display:grid;
grid-template-columns:
repeat(3,1fr);
gap:15px;
margin-top:70px;
}

.card{
padding:25px;
border-radius:20px;
background:#091015;
border:1px solid #1b302d;
}

.card b{
color:#5fffd0;
}

@media(max-width:800px){

h1{
font-size:43px;
}

.grid{
grid-template-columns:1fr;
}

}

</style>
</head>

<body>

<div class="wrap">

<div class="logo">
MATIA // SECURITY CHECK
</div>

<h1>
Authorized<br>
Security Operations.
</h1>

<p>
Secure security-request management,
live client communication and
assessment operations.
</p>

<div class="actions">

<a
class="primary"
href="/request"
>
REQUEST SECURITY CHECK
</a>

<a href="/admin/login">
ADMIN ACCESS
</a>

<a href="/owner/login">
OWNER ACCESS
</a>

</div>

<div class="grid">

<div class="card">
<b>01 / REQUEST</b>
<p>
Submit an authorized assessment request.
</p>
</div>

<div class="card">
<b>02 / REVIEW</b>
<p>
Security staff review authorization
and scope.
</p>
</div>

<div class="card">
<b>03 / LIVE OPS</b>
<p>
Communicate with the security team
in real time.
</p>
</div>

</div>

</div>

</body>
</html>
""")


# ============================================================
# REQUEST PAGE
# ============================================================

REQUEST_PAGE = """
<!doctype html>
<html>
<head>

<meta charset="utf-8">

<title>Security Request</title>

<style>

*{
box-sizing:border-box;
}

body{
margin:0;
background:#040608;
color:#ecfffa;
font-family:Inter,Segoe UI,Arial;
}

.wrap{
max-width:850px;
margin:auto;
padding:50px 20px;
}

.logo{
color:#5fffd0;
font-weight:900;
letter-spacing:4px;
}

.panel{
margin-top:25px;
padding:30px;
border-radius:22px;
background:#091015;
border:1px solid #1b302d;
box-shadow:0 20px 80px #0009;
}

label{
display:block;
margin-top:17px;
margin-bottom:7px;
color:#7e9993;
}

input,
textarea{
width:100%;
padding:14px;
background:#05090d;
border:1px solid #20352f;
border-radius:11px;
color:white;
outline:none;
}

textarea{
min-height:120px;
resize:vertical;
}

button{
width:100%;
margin-top:20px;
padding:15px;
border:0;
border-radius:12px;
background:#35dca4;
font-weight:900;
cursor:pointer;
}

.note{
margin-top:15px;
padding:13px;
border-radius:10px;
background:#08120f;
border:1px solid #19382f;
color:#71918a;
font-size:13px;
}

</style>
</head>

<body>

<div class="wrap">

<div class="logo">
MATIA // SECURITY CHECK
</div>

<div class="panel">

<h1>Security Assessment Request</h1>

<form method="post">

<label>Name</label>

<input
name="name"
maxlength="120"
required
>

<label>Email</label>

<input
name="email"
type="email"
maxlength="180"
required
>

<label>Website / Project</label>

<input
name="web_name"
maxlength="160"
required
>

<label>Target</label>

<input
name="target"
maxlength="500"
placeholder="https://example.com"
required
>

<label>Authorized Scope</label>

<textarea
name="scope"
maxlength="4000"
required
placeholder="Describe the system and authorization..."
></textarea>

<div class="note">
Only submit systems you own or have
explicit permission to assess.
</div>

<button>
CREATE SECURITY REQUEST
</button>

</form>

</div>

</div>

</body>
</html>
"""


@app.route(
    "/request",
    methods=["GET", "POST"]
)
def create_request():

    if request.method == "GET":

        return render_template_string(
            REQUEST_PAGE
        )

    name = clean_text(
        request.form.get("name"),
        120
    )

    email = clean_text(
        request.form.get("email"),
        180
    )

    web_name = clean_text(
        request.form.get("web_name"),
        160
    )

    target = clean_text(
        request.form.get("target"),
        500
    )

    scope = clean_text(
        request.form.get("scope"),
        4000
    )

    if not all([
        name,
        email,
        web_name,
        target,
        scope
    ]):

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
            client_ip
        )
    )

    request_id = cur.lastrowid

    conn.commit()
    conn.close()

    system_message(
        request_id,
        "Request created. Waiting for staff review."
    )

    notify_staff(
        "request",
        "NEW SECURITY REQUEST",
        f"{name} submitted a new request.",
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

<title>
Request #{{ row.id }}
</title>

<style>

*{
box-sizing:border-box;
}

body{
margin:0;
background:
radial-gradient(
circle at 10% 0%,
#00ffc410,
transparent 25%
),
#040608;

color:#eafff9;
font-family:Inter,Segoe UI,Arial;
}

.wrap{
max-width:1200px;
margin:auto;
padding:30px 20px;
}

.top{
display:flex;
justify-content:space-between;
align-items:center;
gap:15px;
}

.logo{
color:#5fffd0;
font-weight:900;
letter-spacing:4px;
}

.status{
padding:9px 14px;
border-radius:999px;
border:1px solid #28463d;
background:#0b1714;
color:#5fffd0;
font-weight:900;
font-size:12px;
}

.grid{
display:grid;
grid-template-columns:
1fr 1.5fr;

gap:18px;

margin-top:20px;
}

.panel{
background:#091015;
border:1px solid #1b302d;
border-radius:20px;
padding:22px;
}

.info{
display:grid;
gap:10px;
}

.info div{
padding:13px;
background:#050b0e;
border:1px solid #172723;
border-radius:11px;
}

.label{
display:block;
font-size:9px;
letter-spacing:2px;
color:#617a75;
margin-bottom:5px;
}

.chat{
height:600px;
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
padding:12px;
margin:8px 0;
border-radius:13px;
background:#101b20;
border:1px solid #20352f;
}

.msg.client{
margin-left:auto;
background:#14382f;
}

.msg.system{
margin-left:auto;
margin-right:auto;
text-align:center;
color:#75908a;
font-size:12px;
}

.time{
font-size:9px;
color:#5e7772;
margin-top:5px;
}

.compose{
display:flex;
gap:8px;
margin-top:10px;
}

.compose input{
flex:1;
padding:13px;
background:#05090d;
border:1px solid #20352f;
border-radius:10px;
color:white;
}

.compose button{
padding:0 18px;
border:0;
border-radius:10px;
background:#35dca4;
font-weight:900;
}

.live{
color:#5fffd0;
font-size:10px;
font-weight:900;
letter-spacing:2px;
}

@media(max-width:850px){

.grid{
grid-template-columns:1fr;
}

.chat{
height:520px;
}

}

</style>
</head>

<body>

<div class="wrap">

<div class="top">

<div class="logo">
MATIA // SECURITY CHECK
</div>

<div
id="status"
class="status"
>
{{ row.status }}
</div>

</div>

<div class="grid">

<div class="panel">

<h2>
REQUEST #{{ row.id }}
</h2>

<div class="info">

<div>
<span class="label">CLIENT</span>
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
<span class="label">SCOPE</span>
{{ row.scope }}
</div>

</div>

</div>

<div class="panel chat">

<div
style="
display:flex;
justify-content:space-between;
"
>

<h3>
LIVE OPERATIONS
</h3>

<div
id="live"
class="live"
>
● WAITING
</div>

</div>

<div
id="messages"
class="messages"
></div>

<div
id="composer"
class="compose"
style="display:none"
>

<input
id="message"
placeholder="Message security staff..."
>

<button
onclick="sendMessage()"
>
SEND
</button>

</div>

</div>

</div>

</div>

<script>

const requestId =
{{ row.id }};

const token =
{{ row.client_token|tojson }};

let lastMessageId = 0;

let audioContext = null;

let audioEnabled = false;


function enableAudio(){

    if(!audioContext){

        audioContext =
            new (
                window.AudioContext ||
                window.webkitAudioContext
            )();

    }

    audioContext.resume();

    audioEnabled = true;
}


document.addEventListener(
    "click",
    enableAudio,
    {once:true}
);


function ring(){

    if(
        !audioEnabled ||
        !audioContext
    ) return;

    const osc =
        audioContext.createOscillator();

    const gain =
        audioContext.createGain();

    osc.connect(gain);

    gain.connect(
        audioContext.destination
    );

    gain.gain.value = 0.04;

    osc.frequency.value = 880;

    osc.start();

    setTimeout(
        () => {
            osc.frequency.value = 660;
        },
        120
    );

    setTimeout(
        () => {
            osc.stop();
        },
        250
    );
}


function esc(value){

    const d =
        document.createElement("div");

    d.textContent =
        value ?? "";

    return d.innerHTML;
}


function renderMessages(messages){

    const box =
        document.getElementById(
            "messages"
        );

    const shouldScroll =
        box.scrollHeight -
        box.scrollTop -
        box.clientHeight < 100;

    box.innerHTML = "";

    for(
        const m of messages
    ){

        const div =
            document.createElement(
                "div"
            );

        let cls = "msg";

        if(
            m.sender === "CLIENT"
        ){
            cls += " client";
        }

        if(
            m.sender === "SYSTEM"
        ){
            cls += " system";
        }

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

    if(shouldScroll){

        box.scrollTop =
            box.scrollHeight;

    }
}


async function load(){

    try{

        const response =
            await fetch(
                `/api/client/${requestId}/data?token=${encodeURIComponent(token)}`,
                {
                    cache:"no-store"
                }
            );

        if(!response.ok)
            return;

        const data =
            await response.json();

        document.getElementById(
            "status"
        ).textContent =
            data.request.status;

        const active =
            [
                "ACCEPTED",
                "IN PROGRESS",
                "COMPLETED"
            ].includes(
                data.request.status
            );

        document.getElementById(
            "composer"
        ).style.display =
            active
            ? "flex"
            : "none";

        document.getElementById(
            "live"
        ).textContent =
            active
            ? "● LIVE CHAT"
            : "● " + data.request.status;

        const latest =
            data.messages.length
            ? data.messages[
                data.messages.length - 1
              ].id
            : 0;

        if(
            lastMessageId &&
            latest > lastMessageId
        ){

            ring();

        }

        lastMessageId =
            latest;

        renderMessages(
            data.messages
        );

    }catch(error){

    }

}


async function sendMessage(){

    enableAudio();

    const input =
        document.getElementById(
            "message"
        );

    const message =
        input.value.trim();

    if(!message)
        return;

    input.disabled = true;

    try{

        const response =
            await fetch(
                `/api/client/${requestId}/message?token=${encodeURIComponent(token)}`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                        "application/json"
                    },
                    body:JSON.stringify({
                        message
                    })
                }
            );

        if(response.ok){

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
.addEventListener(
    "keydown",
    event => {

        if(
            event.key === "Enter"
        ){

            event.preventDefault();

            sendMessage();

        }

    }
);


load();

setInterval(
    load,
    1000
);

</script>

</body>
</html>
"""


@app.route(
    "/status/<int:request_id>"
)
def client_status(request_id):

    token =
        request.args.get(
            "token",
            ""
        )

    row =
        get_request_by_token(
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

@app.route(
    "/api/client/<int:request_id>/data"
)
def client_data(request_id):

    token =
        request.args.get(
            "token",
            ""
        )

    row =
        get_request_by_token(
            request_id,
            token
        )

    if not row:
        abort(404)

    conn = db()

    messages =
        conn.execute(
            """
            SELECT
                id,
                sender,
                message,
                created_at
            FROM messages
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,)
        ).fetchall()

    findings =
        conn.execute(
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

        "messages":
            [
                dict(x)
                for x in messages
            ],

        "findings":
            [
                dict(x)
                for x in findings
            ]

    })


@app.route(
    "/api/client/<int:request_id>/message",
    methods=["POST"]
)
def client_message(request_id):

    token =
        request.args.get(
            "token",
            ""
        )

    row =
        get_request_by_token(
            request_id,
            token
        )

    if not row:
        abort(404)

    if (
        row["status"]
        not in OPEN_CHAT_STATUSES
    ):

        return jsonify({
            "ok": False,
            "error": "Chat is not open."
        }), 400

    data =
        request.get_json(
            silent=True
        ) or {}

    message =
        clean_text(
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
        f"{row['name']}: {message[:180]}",
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

*{
box-sizing:border-box;
}

body{
margin:0;
min-height:100vh;
display:grid;
place-items:center;

background:
radial-gradient(
circle at 50% 0%,
#00ffc412,
transparent 35%
),
#040608;

color:#eafff9;

font-family:
Inter,
Segoe UI,
Arial;
}

.login{
width:min(
430px,
calc(100% - 30px)
);

padding:32px;

background:#091015;

border:1px solid #1d3630;

border-radius:22px;

box-shadow:
0 30px 100px #000c;
}

.logo{
color:#5fffd0;
font-weight:900;
letter-spacing:4px;
}

h1{
font-size:30px;
}

input{
width:100%;
padding:14px;
margin:8px 0 15px;

background:#05090d;

border:1px solid #20352f;

border-radius:11px;

color:white;
}

button{
width:100%;
padding:15px;

border:0;

border-radius:11px;

background:#35dca4;

font-weight:900;

cursor:pointer;
}

.error{
padding:12px;
margin-bottom:15px;

border-radius:10px;

background:#281116;

border:1px solid #58252e;

color:#ff7583;
}

</style>

</head>

<body>

<div class="login">

<div class="logo">
MATIA // SECURITY CHECK
</div>

<h1>
{{ title }}
</h1>

{% if error %}

<div class="error">
{{ error }}
</div>

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

<input
type="hidden"
name="next"
value="{{ next_url }}"
>

<button>
AUTHENTICATE
</button>

</form>

</div>

</body>
</html>
"""


def safe_next(value):

    if not value:
        return None

    if (
        value.startswith("/")
        and not value.startswith("//")
    ):
        return value

    return None


@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    error = None

    next_url =
        request.values.get(
            "next",
            ""
        )

    if request.method == "POST":

        email =
            request.form.get(
                "email",
                ""
            )

        password =
            request.form.get(
                "password",
                ""
            )

        if (
            hmac.compare_digest(
                email,
                ADMIN_EMAIL
            )
            and
            hmac.compare_digest(
                password,
                ADMIN_PASSWORD
            )
        ):

            session.clear()

            session["role"] = "admin"

            destination =
                safe_next(
                    request.form.get(
                        "next",
                        ""
                    )
                )

            if destination:
                return redirect(
                    destination
                )

            return redirect(
                url_for("admin")
            )

        error =
            "Invalid admin credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="ADMIN ACCESS",
        error=error,
        next_url=next_url
    )


@app.route(
    "/owner/login",
    methods=["GET", "POST"]
)
def owner_login():

    error = None

    next_url =
        request.values.get(
            "next",
            ""
        )

    if request.method == "POST":

        email =
            request.form.get(
                "email",
                ""
            )

        password =
            request.form.get(
                "password",
                ""
            )

        if (
            hmac.compare_digest(
                email,
                OWNER_EMAIL
            )
            and
            hmac.compare_digest(
                password,
                OWNER_PASSWORD
            )
        ):

            session.clear()

            session["role"] = "owner"

            destination =
                safe_next(
                    request.form.get(
                        "next",
                        ""
                    )
                )

            if destination:
                return redirect(
                    destination
                )

            return redirect(
                url_for("owner")
            )

        error =
            "Invalid owner credentials."

    return render_template_string(
        LOGIN_PAGE,
        title="OWNER ACCESS",
        error=error,
        next_url=next_url
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD = """
<!doctype html>
<html>
<head>

<meta charset="utf-8">

<title>{{ title }}</title>

<style>

*{
box-sizing:border-box;
}

:root{

--bg:#040608;
--panel:#091015;
--panel2:#0d161b;
--line:#1b302d;
--text:#eafff9;
--muted:#718984;
--green:#5fffd0;
--red:#ff6376;
--yellow:#ffd166;
--blue:#67aaff;

}

body{

margin:0;

background:
radial-gradient(
circle at 10% 0%,
#00ffc410,
transparent 25%
),
radial-gradient(
circle at 100% 100%,
#5168ff0d,
transparent 30%
),

var(--bg);

color:var(--text);

font-family:
Inter,
Segoe UI,
Arial;

}

.layout{

display:grid;

grid-template-columns:
245px 1fr;

min-height:100vh;

}

.sidebar{

background:#05090c;

border-right:
1px solid var(--line);

padding:22px;

position:sticky;

top:0;

height:100vh;

}

.brand{

color:var(--green);

font-size:14px;

font-weight:900;

letter-spacing:3px;

margin-bottom:30px;

}

.nav{

display:grid;

gap:7px;

}

.nav a{

padding:12px;

border-radius:11px;

text-decoration:none;

color:#78918c;

border:1px solid transparent;

}

.nav a:hover,
.nav a.active{

color:var(--green);

background:#0d1918;

border-color:#203b34;

}

.main{

padding:24px;

overflow:auto;

}

.top{

display:flex;

justify-content:space-between;

align-items:center;

gap:15px;

margin-bottom:22px;

}

.title{

font-size:27px;

font-weight:900;

}

.live{

color:var(--green);

font-size:10px;

font-weight:900;

letter-spacing:2px;

margin-top:5px;

}

.dot{

display:inline-block;

width:8px;

height:8px;

border-radius:50%;

background:var(--green);

box-shadow:
0 0 14px var(--green);

}

.bell{

position:relative;

padding:11px 14px;

border-radius:11px;

background:#0b1419;

border:1px solid var(--line);

cursor:pointer;

font-size:17px;

}

.badge{

position:absolute;

right:-6px;

top:-6px;

min-width:19px;

height:19px;

padding:0 5px;

border-radius:20px;

display:grid;

place-items:center;

background:var(--red);

font-size:9px;

font-weight:900;

}

.cards{

display:grid;

grid-template-columns:
repeat(5,1fr);

gap:12px;

}

.card{

padding:18px;

border-radius:17px;

background:
linear-gradient(
145deg,
#0a1217,
#071015
);

border:1px solid var(--line);

}

.label{

font-size:9px;

letter-spacing:2px;

color:var(--muted);

}

.number{

font-size:30px;

font-weight:900;

margin-top:8px;

}

.green{
color:var(--green);
}

.red{
color:var(--red);
}

.yellow{
color:var(--yellow);
}

.blue{
color:var(--blue);
}

.section{

margin-top:17px;

padding:18px;

border-radius:18px;

background:#090f14;

border:1px solid var(--line);

}

.section-head{

display:flex;

justify-content:space-between;

align-items:center;

margin-bottom:12px;

}

.table-wrap{

overflow:auto;

}

table{

width:100%;

border-collapse:collapse;

}

th{

text-align:left;

font-size:9px;

letter-spacing:2px;

color:#607a74;

padding:11px;

border-bottom:
1px solid var(--line);

}

td{

padding:13px 11px;

border-bottom:
1px solid #12221e;

}

tr:hover{

background:#0c171a;

}

.pill{

display:inline-block;

padding:5px 9px;

border-radius:999px;

background:#101d20;

border:1px solid #20352f;

font-size:9px;

font-weight:900;

}

.open{

display:inline-block;

padding:7px 10px;

border-radius:8px;

background:#11251f;

border:1px solid #24483d;

color:var(--green);

text-decoration:none;

font-size:10px;

font-weight:900;

}

.notice-panel{

position:fixed;

right:20px;

top:70px;

width:350px;

max-height:500px;

overflow:auto;

background:#091015;

border:1px solid #24443a;

border-radius:17px;

padding:15px;

box-shadow:0 30px 100px #000e;

display:none;

z-index:100;

}

.notice{

padding:12px;

border-bottom:
1px solid #162622;

}

.notice b{

color:var(--green);

}

.notice small{

display:block;

margin-top:5px;

color:#5e7772;

}

.terminal-link{

color:#ffd166 !important;

}

@media(max-width:1000px){

.layout{
grid-template-columns:1fr;
}

.sidebar{

height:auto;

position:relative;

}

.cards{

grid-template-columns:
repeat(2,1fr);

}

}

@media(max-width:600px){

.cards{

grid-template-columns:1fr;

}

.main{

padding:14px;

}

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

<a
class="active"
href="{{ dashboard_url }}"
>
◉ DASHBOARD
</a>

{% if role == "owner" %}

<a
class="terminal-link"
href="/owner/terminal"
>
⌘ OWNER TERMINAL
</a>

{% endif %}

<a href="/logout">
↪ LOGOUT
</a>

</div>

<div
style="
position:absolute;
bottom:25px;
font-size:10px;
color:#506964;
"
>

VERSION {{ version }}

<br>

ROLE:
{{ role|upper }}

<br>

SYSTEM: ONLINE

</div>

</aside>

<main class="main">

<div class="top">

<div>

<div class="title">
{{ title }}
</div>

<div class="live">

<span class="dot"></span>

LIVE OPERATIONS

</div>

</div>

<div
class="bell"
onclick="toggleNotifications()"
>

🔔

<span
id="badge"
class="badge"
>
0
</span>

</div>

</div>

<div
id="noticePanel"
class="notice-panel"
>

<div
style="
font-weight:900;
margin-bottom:10px;
"
>
LIVE NOTIFICATIONS
</div>

<div
id="notifications"
></div>

</div>

<div class="cards">

<div class="card">

<div class="label">
TOTAL
</div>

<div
id="s_total"
class="number"
>
{{ data.total }}
</div>

</div>

<div class="card">

<div class="label">
PENDING
</div>

<div
id="s_pending"
class="number yellow"
>
{{ data.PENDING }}
</div>

</div>

<div class="card">

<div class="label">
ACCEPTED
</div>

<div
id="s_accepted"
class="number green"
>
{{ data.ACCEPTED }}
</div>

</div>

<div class="card">

<div class="label">
ACTIVE
</div>

<div
id="s_active"
class="number blue"
>
{{ data['IN PROGRESS'] }}
</div>

</div>

<div class="card">

<div class="label">
FINDINGS
</div>

<div
id="s_findings"
class="number red"
>
{{ data.findings }}
</div>

</div>

</div>

<div class="section">

<div class="section-head">

<h3>
SECURITY REQUESTS
</h3>

<span
style="
font-size:10px;
color:#5f7772;
"
>
LIVE • 1 SEC
</span>

</div>

<div class="table-wrap">

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

<td>
#{{ r.id }}
</td>

<td>

<b>
{{ r.name }}
</b>

<br>

<small
style="color:#607974"
>
{{ r.email }}
</small>

</td>

<td>
{{ r.target }}
</td>

<td>

<span class="pill">
{{ r.status }}
</span>

</td>

<td>
{{ r.created_at }}
</td>

<td>

<a
class="open"
href="/admin/client/{{ r.id }}"
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

let audioContext = null;

let audioEnabled = false;


function enableAudio(){

    if(!audioContext){

        audioContext =
            new (
                window.AudioContext ||
                window.webkitAudioContext
            )();

    }

    audioContext.resume();

    audioEnabled = true;
}


document.addEventListener(
    "click",
    enableAudio,
    {once:true}
);


function ring(){

    if(
        !audioEnabled ||
        !audioContext
    ) return;

    const osc =
        audioContext.createOscillator();

    const gain =
        audioContext.createGain();

    osc.connect(gain);

    gain.connect(
        audioContext.destination
    );

    gain.gain.value = 0.04;

    osc.frequency.value = 880;

    osc.start();

    setTimeout(
        () => {
            osc.frequency.value = 660;
        },
        130
    );

    setTimeout(
        () => {
            osc.stop();
        },
        260
    );
}


function escapeHtml(value){

    const d =
        document.createElement("div");

    d.textContent =
        value ?? "";

    return d.innerHTML;
}


function toggleNotifications(){

    const panel =
        document.getElementById(
            "noticePanel"
        );

    panel.style.display =
        panel.style.display === "block"
        ? "none"
        : "block";

}


async function poll(){

    try{

        const response =
            await fetch(
                "/api/staff/notifications",
                {
                    cache:"no-store"
                }
            );

        if(!response.ok)
            return;

        const data =
            await response.json();

        document.getElementById(
            "badge"
        ).textContent =
            data.unread > 99
            ? "99+"
            : data.unread;

        const box =
            document.getElementById(
                "notifications"
            );

        box.innerHTML = "";

        for(
            const n of data.items
        ){

            const div =
                document.createElement(
                    "div"
                );

            div.className =
                "notice";

            div.innerHTML =
                "<b>" +
                escapeHtml(
                    n.title
                ) +
                "</b>" +

                "<div>" +
                escapeHtml(
                    n.body
                ) +
                "</div>" +

                "<small>" +
                escapeHtml(
                    n.created_at
                ) +
                "</small>";

            box.appendChild(div);

        }

        if(
            lastNotificationId &&
            data.latest_id >
            lastNotificationId
        ){

            ring();

        }

        lastNotificationId =
            data.latest_id ||
            lastNotificationId;

        if(data.stats){

            document.getElementById(
                "s_total"
            ).textContent =
                data.stats.total;

            document.getElementById(
                "s_pending"
            ).textContent =
                data.stats.PENDING;

            document.getElementById(
                "s_accepted"
            ).textContent =
                data.stats.ACCEPTED;

            document.getElementById(
                "s_active"
            ).textContent =
                data.stats["IN PROGRESS"];

            document.getElementById(
                "s_findings"
            ).textContent =
                data.stats.findings;

        }

    }catch(error){

    }

}


poll();

setInterval(
    poll,
    1000
);

</script>

</body>
</html>
"""


def render_dashboard(role):

    conn = db()

    rows =
        conn.execute(
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
        )
    )


@app.route("/admin")
@staff_required
def admin():

    return render_dashboard(
        "admin"
    )


@app.route("/owner")
@owner_required
def owner():

    return render_dashboard(
        "owner"
    )


# ============================================================
# STAFF NOTIFICATIONS
# ============================================================

@app.route(
    "/api/staff/notifications"
)
@staff_required
def staff_notifications():

    conn = db()

    rows =
        conn.execute(
            """
            SELECT
                id,
                request_id,
                kind,
                title,
                body,
                created_at,
                read
            FROM notifications
            WHERE audience='staff'
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    unread =
        conn.execute(
            """
            SELECT COUNT(*) c
            FROM notifications
            WHERE audience='staff'
            AND read=0
            """
        ).fetchone()["c"]

    conn.close()

    return jsonify({

        "unread":
            unread,

        "latest_id":
            rows[0]["id"]
            if rows else 0,

        "items":
            [
                dict(x)
                for x in rows
            ],

        "stats":
            stats()

    })


@app.route(
    "/api/staff/notifications/read",
    methods=["POST"]
)
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

    return jsonify({
        "ok": True
    })


# ============================================================
# STAFF CLIENT DETAIL
# ============================================================

STAFF_DETAIL = """
<!doctype html>
<html>
<head>

<meta charset="utf-8">

<title>
Client #{{ row.id }}
</title>

<style>

*{
box-sizing:border-box;
}

body{

margin:0;

background:
radial-gradient(
circle at 10% 0%,
#00ffc410,
transparent 25%
),
#040608;

color:#eafff9;

font-family:
Inter,
Segoe UI,
Arial;

}

.wrap{

max-width:1450px;

margin:auto;

padding:22px;

}

.top{

display:flex;

justify-content:
space-between;

align-items:center;

gap:15px;

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

grid-template-columns:
370px 1fr 370px;

gap:15px;

margin-top:20px;

}

.panel{

background:#090f14;

border:1px solid #1b302d;

border-radius:20px;

padding:18px;

box-shadow:
0 15px 60px #0008;

}

.info{

display:grid;

gap:9px;

}

.info div{

padding:12px;

background:#060c10;

border:1px solid #172723;

border-radius:11px;

}

.label{

display:block;

font-size:9px;

letter-spacing:2px;

color:#617a75;

margin-bottom:5px;

}

.chat{

height:680px;

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

padding:12px;

margin:8px 0;

border-radius:14px;

background:#101b20;

border:1px solid #20352f;

}

.msg.staff{

margin-left:auto;

background:#14382f;

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

margin-top:10px;

}

.compose input{

flex:1;

padding:13px;

background:#05090d;

border:1px solid #20352f;

border-radius:10px;

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

.actiongrid{

display:grid;

grid-template-columns:
1fr 1fr;

gap:8px;

margin-top:15px;

}

textarea{

width:100%;

min-height:90px;

background:#05090d;

border:1px solid #1c3430;

border-radius:10px;

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

font-size:10px;

font-weight:900;

letter-spacing:2px;

}

@media(max-width:1200px){

.grid{

grid-template-columns:
1fr 1fr;

}

}

@media(max-width:800px){

.grid{

grid-template-columns:1fr;

}

.chat{

height:550px;

}

}

</style>

</head>

<body>

<div class="wrap">

<div class="top">

<div>

<div class="logo">
MATIA // SECURITY CHECK
</div>

<div style="margin-top:7px">
CLIENT #{{ row.id }}
</div>

</div>

<a
class="back"
href="{{ '/owner' if role == 'owner' else '/admin' }}"
>
← COMMAND CENTER
</a>

</div>

<div class="grid">

<!-- CLIENT INFO -->

<div class="panel">

<h3>
CLIENT INTEL
</h3>

<div class="info">

<div>

<span class="label">
NAME
</span>

{{ row.name }}

</div>

<div>

<span class="label">
EMAIL
</span>

{{ row.email }}

</div>

<div>

<span class="label">
PROJECT
</span>

{{ row.web_name }}

</div>

<div>

<span class="label">
TARGET
</span>

{{ row.target }}

</div>

<div>

<span class="label">
STATUS
</span>

<b id="status">
{{ row.status }}
</b>

</div>

<div>

<span class="label">
SCOPE
</span>

{{ row.scope }}

</div>

</div>

<h3>
LIFECYCLE
</h3>

<div class="actiongrid">

<button
onclick="setStatus('ACCEPTED')"
>
ACCEPT
</button>

<button
onclick="setStatus('IN PROGRESS')"
>
START
</button>

<button
class="danger"
onclick="setStatus('DECLINED')"
>
DECLINE
</button>

<button
onclick="setStatus('PENDING')"
>
REOPEN
</button>

<button
onclick="setStatus('COMPLETED')"
>
COMPLETE
</button>

</div>

</div>


<!-- LIVE CHAT -->

<div class="panel chat">

<div
style="
display:flex;
justify-content:space-between;
"
>

<h3>
LIVE CLIENT CHANNEL
</h3>

<div class="live">
● LIVE
</div>

</div>

<div
id="messages"
class="messages"
></div>

<div class="compose">

<input
id="message"
placeholder="Message client..."
>

<button
onclick="sendMessage()"
>
SEND
</button>

</div>

</div>


<!-- FINDINGS -->

<div>

<div class="panel">

<h3>
PUBLISH FINDING
</h3>

<input
id="findingTitle"
placeholder="Finding title"
style="
width:100%;
padding:12px;
background:#05090d;
border:1px solid #1c3430;
border-radius:10px;
color:white;
"
>

<br><br>

<select
id="findingSeverity"
>

<option>
INFO
</option>

<option>
LOW
</option>

<option>
MEDIUM
</option>

<option>
HIGH
</option>

<option>
CRITICAL
</option>

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
onclick="publishFinding()"
>
PUBLISH FINDING
</button>

</div>

<div
class="panel"
style="margin-top:15px"
>

<h3>
FINDINGS
</h3>

<div id="activity">
Loading...
</div>

</div>

</div>

</div>

</div>

<script>

const requestId =
{{ row.id }};


function esc(value){

    const d =
        document.createElement("div");

    d.textContent =
        value ?? "";

    return d.innerHTML;

}


async function load(){

    try{

        const response =
            await fetch(
                `/api/staff/client/${requestId}/data`,
                {
                    cache:"no-store"
                }
            );

        if(!response.ok)
            return;

        const data =
            await response.json();

        document.getElementById(
            "status"
        ).textContent =
            data.request.status;

        const box =
            document.getElementById(
                "messages"
            );

        const shouldScroll =
            box.scrollHeight -
            box.scrollTop -
            box.clientHeight < 120;

        box.innerHTML = "";

        for(
            const m of data.messages
        ){

            const div =
                document.createElement(
                    "div"
                );

            let cls = "msg";

            if(
                m.sender === "ADMIN" ||
                m.sender === "OWNER"
            ){

                cls += " staff";

            }

            if(
                m.sender === "SYSTEM"
            ){

                cls += " system";

            }

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

        if(shouldScroll){

            box.scrollTop =
                box.scrollHeight;

        }

        let html = "";

        for(
            const f of data.findings
        ){

            html +=

            "<div style='padding:10px;border-bottom:1px solid #172724'>" +

            "<b>" +
            esc(f.title) +
            "</b>" +

            "<br>" +

            "<small>" +
            esc(f.severity) +
            "</small>" +

            "<br>" +

            "<small style='color:#6f8882'>" +
            esc(f.created_at) +
            "</small>" +

            "</div>";

        }

        document.getElementById(
            "activity"
        ).innerHTML =
            html ||
            "No findings yet.";

    }catch(error){

    }

}


async function sendMessage(){

    const input =
        document.getElementById(
            "message"
        );

    const message =
        input.value.trim();

    if(!message)
        return;

    input.disabled = true;

    try{

        const response =
            await fetch(
                `/api/staff/client/${requestId}/message`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                        "application/json"
                    },
                    body:JSON.stringify({
                        message
                    })
                }
            );

        if(response.ok){

            input.value = "";

            await load();

        }

    }finally{

        input.disabled = false;

        input.focus();

    }

}


async function setStatus(
    status
){

    const response =
        await fetch(
            `/api/staff/client/${requestId}/status`,
            {
                method:"POST",
                headers:{
                    "Content-Type":
                    "application/json"
                },
                body:JSON.stringify({
                    status
                })
            }
        );

    const data =
        await response
            .json()
            .catch(
                () => ({})
            );

    if(!response.ok){

        alert(
            data.error ||
            "Status update failed."
        );

        return;

    }

    await load();

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


    if(
        !payload.title ||
        !payload.description
    ){

        alert(
            "Title and description required."
        );

        return;

    }


    const response =
        await fetch(
            `/staff/client/${requestId}/finding`,
            {
                method:"POST",
                headers:{
                    "Content-Type":
                    "application/json"
                },
                body:JSON.stringify(
                    payload
                )
            }
        );


    if(response.ok){

        document.getElementById(
            "findingTitle"
        ).value = "";

        document.getElementById(
            "findingDescription"
        ).value = "";

        document.getElementById(
            "findingEvidence"
        ).value = "";

        document.getElementById(
            "findingRecommendation"
        ).value = "";

        await load();

    }else{

        alert(
            "Could not publish finding."
        );

    }

}


document
.getElementById("message")
.addEventListener(
    "keydown",
    event => {

        if(
            event.key === "Enter"
        ){

            event.preventDefault();

            sendMessage();

        }

    }
);


load();

setInterval(
    load,
    1000
);

</script>

</body>
</html>
"""


@app.route(
    "/admin/client/<int:request_id>"
)
@staff_required
def staff_client(request_id):

    row =
        get_request(
            request_id
        )

    if not row:
        abort(404)

    return render_template_string(
        STAFF_DETAIL,
        row=row,
        role=current_role()
    )


# ============================================================
# STAFF CLIENT API
# ============================================================

@app.route(
    "/api/staff/client/<int:request_id>/data"
)
@staff_required
def staff_client_data(request_id):

    row =
        get_request(
            request_id
        )

    if not row:
        abort(404)

    conn = db()

    messages =
        conn.execute(
            """
            SELECT
                id,
                sender,
                message,
                created_at
            FROM messages
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,)
        ).fetchall()

    findings =
        conn.execute(
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

        "request":
            dict(row),

        "messages":
            [
                dict(x)
                for x in messages
            ],

        "findings":
            [
                dict(x)
                for x in findings
            ]

    })


@app.route(
    "/api/staff/client/<int:request_id>/status",
    methods=["POST"]
)
@staff_required
def staff_client_status(request_id):

    data =
        request.get_json(
            silent=True
        ) or {}

    status =
        clean_text(
            data.get("status"),
            50
        )

    if status not in STATUS_ORDER:

        return jsonify({
            "ok": False,
            "error": "Invalid status."
        }), 400

    ok, message =
        set_status(
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
def staff_client_message(
    request_id
):

    row =
        get_request(
            request_id
        )

    if not row:
        abort(404)

    if (
        row["status"]
        not in OPEN_CHAT_STATUSES
    ):

        return jsonify({
            "ok": False,
            "error": "Chat is not open."
        }), 400

    data =
        request.get_json(
            silent=True
        ) or {}

    message =
        clean_text(
            data.get("message"),
            2000
        )

    if not message:

        return jsonify({
            "ok": False,
            "error": "Empty message."
        }), 400

    sender =
        current_role().upper()

    add_message(
        request_id,
        sender,
        message
    )

    notify_client(
        request_id,
        "message",
        "NEW SECURITY MESSAGE",
        f"{sender}: {message[:180]}"
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
def create_finding(
    request_id
):

    row =
        get_request(
            request_id
        )

    if not row:
        abort(404)

    data =
        request.get_json(
            silent=True
        ) or {}

    title =
        clean_text(
            data.get("title"),
            200
        )

    severity =
        clean_text(
            data.get("severity"),
            20
        ).upper()

    description =
        clean_text(
            data.get("description"),
            5000
        )

    evidence =
        clean_text(
            data.get("evidence"),
            5000
        )

    recommendation =
        clean_text(
            data.get("recommendation"),
            5000
        )

    if not title or not description:

        return jsonify({
            "ok": False,
            "error":
                "Title and description required."
        }), 400

    if severity not in SEVERITIES:

        return jsonify({
            "ok": False,
            "error":
                "Invalid severity."
        }), 400

    conn = db()

    cur =
        conn.execute(
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

    finding_id =
        cur.lastrowid

    conn.commit()
    conn.close()

    system_message(
        request_id,
        f"New finding: {title} [{severity}]"
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
        "finding_id":
            finding_id
    })


# ============================================================
# OWNER TERMINAL
# ============================================================

OWNER_TERMINAL = """
<!doctype html>
<html>
<head>

<meta charset="utf-8">

<title>
MATIA OWNER TERMINAL
</title>

<style>

*{
box-sizing:border-box;
}

body{

margin:0;

background:#020403;

color:#63ffd0;

font-family:
"Courier New",
Consolas,
monospace;

}

.terminal{

min-height:100vh;

padding:20px;

}

.header{

display:flex;

justify-content:
space-between;

padding:14px;

background:#06100d;

border:
1px solid #164337;

border-radius:
12px 12px 0 0;

}

.title{

font-weight:900;

letter-spacing:3px;

}

.back{

color:#6acdb2;

text-decoration:none;

}

.screen{

min-height:
calc(100vh - 115px);

padding:18px;

border:
1px solid #164337;

border-top:0;

background:

radial-gradient(
circle at 50% 0%,
#00ff9d08,
transparent 40%
),

#020403;

overflow:auto;

}

.line{

margin:5px 0;

white-space:pre-wrap;

}

.inputline{

display:flex;

gap:8px;

margin-top:10px;

}

.prompt{

color:#3fffc0;

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

</style>

</head>

<body>

<div class="terminal">

<div class="header">

<div class="title">
MATIA // OWNER TERMINAL
</div>

<a
class="back"
href="/owner"
>
← DASHBOARD
</a>

</div>

<div
class="screen"
id="screen"
>

<div class="line">
MATIA SECURITY CHECK OWNER SHELL {{ version }}
</div>

<div class="line">
APPLICATION ADMINISTRATION CONSOLE
</div>

<div class="line">
Type "help" to list commands.
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
document.getElementById(
    "command"
);

const output =
document.getElementById(
    "output"
);


function print(text){

    const div =
        document.createElement(
            "div"
        );

    div.className =
        "line";

    div.textContent =
        text;

    output.appendChild(div);

    window.scrollTo(
        0,
        document.body.scrollHeight
    );

}


async function runCommand(){

    const command =
        input.value.trim();

    if(!command)
        return;

    print(
        "owner@matia:~$ " +
        command
    );

    input.value = "";

    try{

        const response =
            await fetch(
                "/owner/command",
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                        "application/json"
                    },
                    body:JSON.stringify({
                        command
                    })
                }
            );

        const data =
            await response.json();

        if(data.clear){

            output.innerHTML =
                "";

            return;

        }

        if(data.output){

            for(
                const line of
                data.output.split(
                    "\\n"
                )
            ){

                print(line);

            }

        }

    }catch(error){

        print(
            "ERROR: terminal offline."
        );

    }

}


input.addEventListener(
    "keydown",
    event => {

        if(
            event.key === "Enter"
        ){

            runCommand();

        }

    }
);

</script>

</body>
</html>
"""


COMMANDS = {

    "help":
        "Show command list",

    "clear":
        "Clear terminal",

    "status":
        "Show client status",

    "stats":
        "Application statistics",

    "clients":
        "List clients",

    "pending":
        "List pending requests",

    "accepted":
        "List accepted requests",

    "active":
        "List active requests",

    "completed":
        "List completed requests",

    "declined":
        "List declined requests",

    "client <id>":
        "Client information",

    "accept <id>":
        "Accept request",

    "decline <id>":
        "Decline request",

    "start <id>":
        "Start request",

    "complete <id>":
        "Complete request",

    "reopen <id>":
        "Reopen request",

    "message <id> <text>":
        "Send client message",

    "findings <id>":
        "Show findings",

    "findings-total":
        "Total findings",

    "notify <text>":
        "Create notification",

    "announce <text>":
        "Owner announcement",

    "audit":
        "Show audit events",

    "version":
        "Application version",

    "time":
        "Server time",

    "db":
        "Database status",

    "requests-count":
        "Request count",

    "messages-count":
        "Message count",

    "notifications-count":
        "Notification count",

    "critical":
        "Critical findings",

    "high":
        "High findings",

    "medium":
        "Medium findings",

    "low":
        "Low findings",

    "info":
        "Informational findings",

    "whoami":
        "Current role",

    "ping":
        "Health check",

    "online":
        "Online state",

    "maintenance":
        "Maintenance status",
}


def list_requests(
    status=None
):

    conn = db()

    if status:

        rows =
            conn.execute(
                """
                SELECT *
                FROM requests
                WHERE status=?
                ORDER BY id DESC
                LIMIT 50
                """,
                (status,)
            ).fetchall()

    else:

        rows =
            conn.execute(
                """
                SELECT *
                FROM requests
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()

    conn.close()

    if not rows:
        return "No results."

    return "\n".join(

        f"#{r['id']} | "
        f"{r['name']} | "
        f"{r['status']} | "
        f"{r['target']}"

        for r in rows
    )


def execute_command(
    command
):

    command =
        command.strip()

    if not command:
        return ""

    parts =
        command.split()

    cmd =
        parts[0].lower()

    args =
        parts[1:]


    if cmd == "help":

        lines = [
            "======================================",
            " MATIA // OWNER COMMAND CENTER",
            "======================================",
        ]

        for name, desc in COMMANDS.items():

            lines.append(
                f"{name:<30} {desc}"
            )

        lines.extend([
            "",
            "Application administration only.",
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


    if cmd in {
        "ping",
        "online"
    }:

        return (
            "PONG // "
            "MATIA SECURITY CHECK ONLINE"
        )


    if cmd == "stats":

        s = stats()

        return "\n".join([

            f"TOTAL       : {s['total']}",

            f"PENDING     : "
            f"{s[PENDING]}",

            f"ACCEPTED    : "
            f"{s[ACCEPTED]}",

            f"IN PROGRESS : "
            f"{s[IN_PROGRESS]}",

            f"COMPLETED   : "
            f"{s[COMPLETED]}",

            f"DECLINED    : "
            f"{s[DECLINED]}",

            f"FINDINGS    : "
            f"{s['findings']}",

        ])


    aliases = {

        "pending":
            PENDING,

        "accepted":
            ACCEPTED,

        "active":
            IN_PROGRESS,

        "completed":
            COMPLETED,

        "declined":
            DECLINED,

    }


    if cmd == "clients":

        return list_requests()


    if cmd in aliases:

        return list_requests(
            aliases[cmd]
        )


    if cmd in {
        "client",
        "status",
        "accept",
        "decline",
        "start",
        "complete",
        "reopen",
        "findings"
    }:

        if not args:

            return (
                f"Usage: "
                f"{cmd} <id>"
            )

        request_id =
            safe_int(
                args[0]
            )

        if request_id < 1:

            return "Invalid client ID."


        row =
            get_request(
                request_id
            )

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

            "accept":
                ACCEPTED,

            "decline":
                DECLINED,

            "start":
                IN_PROGRESS,

            "complete":
                COMPLETED,

            "reopen":
                PENDING,

        }


        if cmd in transitions:

            ok, message =
                set_status(
                    request_id,
                    transitions[cmd],
                    "OWNER"
                )

            return message


        if cmd == "findings":

            conn = db()

            rows =
                conn.execute(
                    """
                    SELECT *
                    FROM findings
                    WHERE request_id=?
                    ORDER BY id DESC
                    """,
                    (request_id,)
                ).fetchall()

            conn.close()

            if not rows:
                return "No findings."

            return "\n".join(

                f"#{x['id']} | "
                f"{x['severity']} | "
                f"{x['title']}"

                for x in rows
            )


    if cmd == "message":

        if len(args) < 2:

            return (
                "Usage: "
                "message <id> <text>"
            )

        request_id =
            safe_int(
                args[0]
            )

        row =
            get_request(
                request_id
            )

        if not row:
            return "Client not found."

        message =
            " ".join(
                args[1:]
            )

        if (
            row["status"]
            not in OPEN_CHAT_STATUSES
        ):

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
            message[:180]
        )

        audit_action(
            "OWNER",
            "TERMINAL MESSAGE",
            request_id
        )

        return "Message sent."


    if cmd in {
        "notify",
        "announce"
    }:

        if not args:

            return (
                f"Usage: "
                f"{cmd} <text>"
            )

        message =
            " ".join(
                args
            )

        notify_staff(
            "announcement",
            "OWNER ANNOUNCEMENT",
            message
        )

        return "Notification created."


    if cmd in {
        "findings-total",
        "critical",
        "high",
        "medium",
        "low",
        "info"
    }:

        conn = db()

        if cmd == "findings-total":

            count =
                conn.execute(
                    """
                    SELECT COUNT(*) c
                    FROM findings
                    """
                ).fetchone()["c"]

            conn.close()

            return (
                f"TOTAL FINDINGS: "
                f"{count}"
            )

        severity =
            cmd.upper()

        count =
            conn.execute(
                """
                SELECT COUNT(*) c
                FROM findings
                WHERE severity=?
                """,
                (severity,)
            ).fetchone()["c"]

        conn.close()

        return (
            f"{severity}: "
            f"{count}"
        )


    if cmd == "requests-count":

        conn = db()

        count =
            conn.execute(
                """
                SELECT COUNT(*) c
                FROM requests
                """
            ).fetchone()["c"]

        conn.close()

        return f"REQUESTS: {count}"


    if cmd == "messages-count":

        conn = db()

        count =
            conn.execute(
                """
                SELECT COUNT(*) c
                FROM messages
                """
            ).fetchone()["c"]

        conn.close()

        return f"MESSAGES: {count}"


    if cmd == "notifications-count":

        conn = db()

        count =
            conn.execute(
                """
                SELECT COUNT(*) c
                FROM notifications
                """
            ).fetchone()["c"]

        conn.close()

        return (
            f"NOTIFICATIONS: "
            f"{count}"
        )


    if cmd == "audit":

        conn = db()

        rows =
            conn.execute(
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

            f"#{x['id']} | "
            f"{x['created_at']} | "
            f"{x['actor']} | "
            f"{x['action']}"

            for x in rows
        )


    if cmd == "db":

        try:

            size =
                os.path.getsize(
                    DB_PATH
                )

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
        "Type 'help' to list commands."
    )


@app.route(
    "/owner/terminal"
)
@owner_required
def owner_terminal():

    return render_template_string(
        OWNER_TERMINAL,
        version=VERSION
    )


@app.route(
    "/owner/command",
    methods=["POST"]
)
@owner_required
def owner_command():

    data =
        request.get_json(
            silent=True
        ) or {}

    command =
        clean_text(
            data.get("command"),
            2000
        )

    if not command:

        return jsonify({
            "ok": False,
            "output": ""
        })


    output =
        execute_command(
            command
        )


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
# REPORT
# ============================================================

@app.route(
    "/staff/client/<int:request_id>/report"
)
@staff_required
def report(request_id):

    row =
        get_request(
            request_id
        )

    if not row:
        abort(404)

    conn = db()

    findings =
        conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,)
        ).fetchall()

    conn.close()

    return render_template_string(
        """
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>
Security Report
</title>

<style>

body{

background:#040608;

color:#eafff9;

font-family:
Arial,
sans-serif;

padding:35px;

}

.report{

max-width:900px;

margin:auto;

padding:30px;

background:#091015;

border:1px solid #20352f;

border-radius:20px;

}

h1,
h2{

color:#5fffd0;

}

.finding{

padding:18px;

margin-top:15px;

border:1px solid #20352f;

border-radius:14px;

}

small{

color:#6e8882;

}

</style>

</head>

<body>

<div class="report">

<h1>
MATIA // SECURITY CHECK
</h1>

<h2>
Security Assessment Report #{{ row.id }}
</h2>

<p>
<b>Client:</b>
{{ row.name }}
</p>

<p>
<b>Project:</b>
{{ row.web_name }}
</p>

<p>
<b>Target:</b>
{{ row.target }}
</p>

<p>
<b>Status:</b>
{{ row.status }}
</p>

<hr>

<h2>
Findings
</h2>

{% if findings %}

{% for f in findings %}

<div class="finding">

<h3>
{{ f.title }}
</h3>

<small>
{{ f.severity }}
•
{{ f.created_at }}
</small>

<p>
{{ f.description }}
</p>

{% if f.evidence %}

<p>

<b>
Evidence
</b>

<br>

{{ f.evidence }}

</p>

{% endif %}

{% if f.recommendation %}

<p>

<b>
Recommendation
</b>

<br>

{{ f.recommendation }}

</p>

{% endif %}

</div>

{% endfor %}

{% else %}

<p>
No findings published.
</p>

{% endif %}

</div>

</body>

</html>
        """,
        row=row,
        findings=findings
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/healthz")
def healthz():

    return jsonify({

        "status": "ok",

        "app":
            APP_NAME,

        "version":
            VERSION,

        "time":
            now()

    })


# ============================================================
# ERRORS
# ============================================================

@app.errorhandler(403)
def forbidden(error):

    return render_template_string(
        """
        <body style="
        background:#040608;
        color:#ff6577;
        font-family:monospace;
        padding:50px">

        <h1>
        403 // ACCESS DENIED
        </h1>

        <p>
        You do not have permission to access this resource.
        </p>

        <a
        href="/"
        style="color:#5fffd0"
        >
        RETURN HOME
        </a>

        </body>
        """
    ), 403


@app.errorhandler(404)
def not_found(error):

    return render_template_string(
        """
        <body style="
        background:#040608;
        color:#5fffd0;
        font-family:monospace;
        padding:50px">

        <h1>
        404 // NOT FOUND
        </h1>

        <a
        href="/"
        style="color:#5fffd0"
        >
        RETURN HOME
        </a>

        </body>
        """
    ), 404


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    port =
        int(
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
