import os
import html
import secrets
import socket
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, redirect, session, url_for, abort
from flask_socketio import SocketIO, join_room

APP_NAME = "MATIA // SECURITY CHECK"
ADMIN_EMAIL = os.getenv(
    "MATIA_ADMIN_EMAIL",
    "kleimatia1@gmail.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv("MATIA_ADMIN_PASSWORD")
SECRET_KEY = os.getenv("MATIA_SECRET_KEY")
DB_FILE = os.getenv("MATIA_DB_FILE", "matia_security.db")
PORT = int(os.getenv("PORT", "5000"))

if not ADMIN_PASSWORD:
    raise RuntimeError("MATIA_ADMIN_PASSWORD is missing.")

if not SECRET_KEY:
    raise RuntimeError("MATIA_SECRET_KEY is missing.")

app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("COOKIE_SECURE", "true").lower() == "true"
    ),
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# ============================================================
# CSS
# ============================================================

CSS = r'''
:root{
    --bg:#05070b;
    --panel:#0c1119;
    --panel2:#111925;
    --border:#202b3b;
    --text:#eef4ff;
    --muted:#8fa0b7;
    --a:#6f7cff;
    --cyan:#00e5ff;
    --green:#27e995;
    --red:#ff4f69;
    --yellow:#ffc857;
    --orange:#ff914d;
}

*{
    box-sizing:border-box
}

body{
    margin:0;
    color:var(--text);
    font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;
    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(111,124,255,.16),
            transparent 27%
        ),
        radial-gradient(
            circle at 100% 10%,
            rgba(0,229,255,.09),
            transparent 25%
        ),
        linear-gradient(
            180deg,
            #04060a,
            #080c12 55%,
            #05070b
        );
    min-height:100vh
}

a{
    text-decoration:none;
    color:inherit
}

.wrap{
    width:min(1180px,92%);
    margin:auto
}

.top{
    position:sticky;
    top:0;
    z-index:20;
    background:rgba(4,6,10,.78);
    backdrop-filter:blur(14px);
    border-bottom:1px solid rgba(255,255,255,.06)
}

.nav{
    height:72px;
    display:flex;
    align-items:center;
    justify-content:space-between
}

.brand{
    display:flex;
    gap:12px;
    align-items:center;
    font-weight:900;
    letter-spacing:.5px
}

.logo{
    height:38px;
    width:38px;
    border-radius:12px;
    display:grid;
    place-items:center;
    background:
        linear-gradient(
            135deg,
            var(--a),
            var(--cyan)
        );
    color:#03060b;
    box-shadow:
        0 0 28px
        rgba(111,124,255,.35)
}

.brand small{
    display:block;
    color:var(--muted);
    font-size:9px;
    letter-spacing:1.6px;
    margin-top:2px
}

.links{
    display:flex;
    gap:5px
}

.links a{
    padding:10px 12px;
    border-radius:10px;
    color:var(--muted)
}

.links a:hover{
    background:rgba(255,255,255,.05);
    color:var(--text)
}

.hero{
    padding:88px 0 40px
}

.hero-grid,
.two{
    display:grid;
    grid-template-columns:1.15fr .85fr;
    gap:20px
}

.hero h1{
    font-size:clamp(44px,7vw,82px);
    line-height:.94;
    letter-spacing:-4px;
    margin:8px 0 20px
}

.grad{
    background:
        linear-gradient(
            90deg,
            #fff,
            var(--cyan),
            #98a0ff
        );
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent
}

.muted{
    color:var(--muted);
    line-height:1.75
}

.status{
    display:flex;
    gap:9px;
    align-items:center;
    color:var(--green);
    font-weight:800;
    font-size:13px;
    letter-spacing:.4px
}

.dot{
    height:8px;
    width:8px;
    border-radius:50%;
    background:var(--green);
    box-shadow:0 0 16px var(--green)
}

.panel{
    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.035),
            rgba(255,255,255,.01)
        ),
        var(--panel);
    border:1px solid var(--border);
    border-radius:20px;
    box-shadow:0 20px 60px rgba(0,0,0,.28)
}

.card{
    padding:22px
}

.code{
    padding:15px;
    border:1px solid var(--border);
    border-radius:14px;
    background:#05080c;
    font:
        12px/1.9
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;
    color:#b6c7dd
}

.stats,
.kpis,
.cards{
    display:grid;
    gap:12px
}

.stats{
    grid-template-columns:repeat(3,1fr);
    margin-top:24px
}

.kpis{
    grid-template-columns:repeat(4,1fr)
}

.cards{
    grid-template-columns:repeat(3,1fr)
}

.stat,
.kpi{
    padding:18px;
    border:1px solid var(--border);
    border-radius:15px;
    background:rgba(255,255,255,.02)
}

.stat strong,
.kpi strong{
    display:block;
    font-size:25px;
    margin-bottom:4px
}

.stat span,
.kpi span{
    font-size:12px;
    color:var(--muted)
}

.section{
    padding:34px 0
}

.title{
    font-size:32px;
    margin:0 0 9px
}

.sub{
    color:var(--muted);
    margin:0 0 22px
}

.form{
    width:min(900px,100%);
    margin:30px auto 65px
}

.grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:16px
}

.field{
    display:flex;
    flex-direction:column;
    gap:8px
}

.full{
    grid-column:1/-1
}

label{
    font-size:13px;
    font-weight:800;
    color:#ccd7e7
}

input,
textarea,
select{
    width:100%;
    padding:14px 15px;
    border:1px solid var(--border);
    background:#080c12;
    color:var(--text);
    border-radius:13px;
    outline:none;
    font:inherit
}

input:focus,
textarea:focus,
select:focus{
    border-color:var(--a);
    box-shadow:
        0 0 0 3px
        rgba(111,124,255,.12)
}

textarea{
    min-height:125px;
    resize:vertical
}

.check{
    display:flex;
    align-items:flex-start;
    gap:9px;
    color:var(--muted);
    font-size:13px;
    line-height:1.6
}

.check input{
    width:auto;
    margin-top:4px
}

.btn{
    border:0;
    border-radius:12px;
    padding:13px 17px;
    font-weight:900;
    color:#fff;
    cursor:pointer;
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:8px
}

.primary{
    background:
        linear-gradient(
            135deg,
            var(--a),
            #8f60ff
        );
    box-shadow:
        0 12px 28px
        rgba(111,124,255,.2)
}

.dark{
    background:#111824;
    border:1px solid var(--border)
}

.green{
    background:
        linear-gradient(
            135deg,
            #1dcc7e,
            #0ca55e
        )
}

.red{
    background:
        linear-gradient(
            135deg,
            #ff536a,
            #e43e57
        )
}

.notice{
    padding:13px 15px;
    border-radius:12px;
    margin-bottom:15px;
    border:1px solid var(--border)
}

.error{
    background:rgba(255,79,105,.09);
    color:#ffb3bf;
    border-color:rgba(255,79,105,.25)
}

.table{
    overflow:auto
}

.table table{
    width:100%;
    border-collapse:collapse
}

.table th,
.table td{
    padding:13px;
    border-bottom:1px solid var(--border);
    text-align:left;
    white-space:nowrap
}

.table th{
    font-size:11px;
    color:#93a4ba;
    text-transform:uppercase
}

.badge{
    display:inline-flex;
    padding:6px 10px;
    border-radius:999px;
    font-size:11px;
    font-weight:900;
    border:1px solid transparent
}

.pending{
    background:rgba(255,200,87,.08);
    color:#ffd87a;
    border-color:rgba(255,200,87,.2)
}

.accepted,
.completed{
    background:rgba(39,233,149,.08);
    color:#7ff2b6;
    border-color:rgba(39,233,149,.2)
}

.progress{
    background:rgba(0,229,255,.08);
    color:#77efff;
    border-color:rgba(0,229,255,.2)
}

.declined{
    background:rgba(255,79,105,.08);
    color:#ff9cac;
    border-color:rgba(255,79,105,.2)
}

.chat{
    display:flex;
    flex-direction:column;
    min-height:520px
}

.chatbox{
    flex:1;
    max-height:520px;
    overflow:auto;
    padding:18px;
    display:flex;
    flex-direction:column;
    gap:10px
}

.msg{
    max-width:82%;
    padding:11px 13px;
    border:1px solid var(--border);
    border-radius:14px;
    background:#0a0f16
}

.msg.admin{
    align-self:flex-end;
    background:rgba(111,124,255,.12);
    border-color:rgba(111,124,255,.22)
}

.msg.client{
    align-self:flex-start
}

.who{
    font-size:10px;
    letter-spacing:.8px;
    text-transform:uppercase;
    color:var(--muted);
    font-weight:900;
    margin-bottom:5px
}

.time{
    font-size:10px;
    color:#69778b;
    margin-top:6px
}

.chatform{
    display:flex;
    gap:9px;
    padding:13px;
    border-top:1px solid var(--border)
}

.chatform input{
    flex:1
}

.finding{
    padding:20px;
    margin-bottom:12px
}

.finding h3{
    margin:4px 0 8px
}

.sev{
    font-weight:900
}

.sev.critical{
    color:#ff6176
}

.sev.high{
    color:#ff8c67
}

.sev.medium{
    color:#ffd36d
}

.sev.low{
    color:#5fe6a4
}

.sev.info{
    color:#75ddff
}

.head{
    display:flex;
    justify-content:space-between;
    gap:15px;
    align-items:flex-start;
    margin-bottom:20px
}

.actions{
    display:flex;
    gap:8px;
    flex-wrap:wrap
}

.empty{
    text-align:center;
    padding:30px;
    color:var(--muted)
}

.footer{
    text-align:center;
    padding:50px 0;
    color:#65748a;
    font-size:12px
}

.login{
    width:min(480px,92%);
    margin:80px auto
}

.login .panel{
    padding:28px
}

@media(max-width:900px){

    .hero-grid,
    .two{
        grid-template-columns:1fr
    }

    .cards{
        grid-template-columns:1fr
    }

    .kpis{
        grid-template-columns:repeat(2,1fr)
    }
}

@media(max-width:650px){

    .links{
        display:none
    }

    .grid{
        grid-template-columns:1fr
    }

    .full{
        grid-column:auto
    }

    .stats{
        grid-template-columns:1fr
    }

    .hero h1{
        letter-spacing:-2px
    }
}
'''


# ============================================================
# HELPERS
# ============================================================

def esc(v):
    return html.escape(
        str(v or ""),
        quote=True
    )


def now():
    return datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def db():
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()

    c.execute("""
        CREATE TABLE IF NOT EXISTS requests(
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

    c.execute("""
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    c.commit()
    c.close()


def get_request(rid):
    c = db()

    row = c.execute(
        "SELECT * FROM requests WHERE id=?",
        (rid,)
    ).fetchone()

    c.close()

    return row


def authorized(rid, token):

    if not token:
        return False

    c = db()

    row = c.execute(
        """
        SELECT id
        FROM requests
        WHERE id=?
        AND client_token=?
        """,
        (
            rid,
            token
        )
    ).fetchone()

    c.close()

    return row is not None


def valid_target(target):

    try:
        p = urlparse(
            target.strip()
        )

        return (
            p.scheme in ("http", "https")
            and bool(p.netloc)
        )

    except Exception:
        return False


def resolve_target(target):

    try:
        host = urlparse(
            target
        ).hostname

        return (
            socket.gethostbyname(host)
            if host
            else None
        )

    except Exception:
        return None


def admin_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if not session.get(
            "admin_logged_in"
        ):
            return redirect(
                url_for("admin_login")
            )

        return fn(
            *args,
            **kwargs
        )

    return wrapper


def sev_class(v):

    v = (v or "").upper()

    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low"
    }.get(v, "info")


def page(title, body, script=""):

    return f'''<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    {esc(title)} — {APP_NAME}
</title>

<style>
{CSS}
</style>

<script
    src="https://cdn.socket.io/4.8.1/socket.io.min.js"
></script>

</head>

<body>

<div class="top">

    <div class="wrap nav">

        <a
            class="brand"
            href="/"
        >

            <div class="logo">
                M
            </div>

            <div>

                MATIA // SECURITY

                <small>
                    AUTHORIZED SECURITY CHECKS
                </small>

            </div>

        </a>

        <div class="links">

            <a href="/">
                Home
            </a>

            <a href="/request">
                Request
            </a>

            <a href="/admin/login">
                Admin
            </a>

        </div>

    </div>

</div>

<main>
{body}
</main>

<div class="footer">

    MATIA // SECURITY CHECK
    ·
    Authorized Security Assessment Portal

</div>

<script>
{script}
</script>

</body>

</html>'''


def message_html(messages):

    if not messages:
        return (
            '<div class="empty">'
            'No messages yet.'
            '</div>'
        )

    out = []

    for m in messages:

        role = (
            "admin"
            if m["sender"] == "admin"
            else "client"
        )

        out.append(
            f'''
            <div class="msg {role}">

                <div class="who">
                    {esc(m["sender"])}
                </div>

                <div>
                    {esc(m["message"])}
                </div>

                <div class="time">
                    {esc(m["created_at"])}
                </div>

            </div>
            '''
        )

    return "".join(out)


def finding_cards(findings):

    if not findings:

        return (
            '<div class="panel empty">'
            'No findings published yet.'
            '</div>'
        )

    out = []

    for f in findings:

        s = sev_class(
            f["severity"]
        )

        out.append(
            f'''
            <div class="panel finding">

                <div class="sev {s}">
                    {esc(f["severity"])}
                </div>

                <h3>
                    {esc(f["title"])}
                </h3>

                <p class="muted">

                    <b>
                        Description
                    </b>

                    <br>

                    {esc(f["description"])}

                </p>

                <p class="muted">

                    <b>
                        Evidence
                    </b>

                    <br>

                    {esc(f["evidence"])}

                </p>

                <p class="muted">

                    <b>
                        Recommendation
                    </b>

                    <br>

                    {esc(f["recommendation"])}

                </p>

            </div>
            '''
        )

    return "".join(out)


# ============================================================
# SOCKET.IO
# ============================================================

@socketio.on("join_admin")
def join_admin():

    if session.get(
        "admin_logged_in"
    ):
        join_room("admin")


@socketio.on("join_request")
def join_request(data):

    try:
        rid = int(
            data.get("request_id")
        )
    except Exception:
        return

    join_room(
        f"request_{rid}"
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    body = '''
<section class="hero">

    <div class="wrap hero-grid">

        <div>

            <div class="status">

                <span class="dot"></span>

                SECURITY PORTAL ONLINE

            </div>

            <h1>

                Find the weak points

                <span class="grad">
                    before attackers do.
                </span>

            </h1>

            <p class="muted">

                MATIA // SECURITY CHECK is an
                authorized website security
                assessment portal with client
                tracking, live chat and reporting.

            </p>

            <div
                class="actions"
                style="margin-top:22px"
            >

                <a
                    class="btn primary"
                    href="/request"
                >
                    Start Security Check →
                </a>

                <a
                    class="btn dark"
                    href="#how"
                >
                    How it works
                </a>

            </div>

            <div class="stats">

                <div class="stat">

                    <strong>
                        01
                    </strong>

                    <span>
                        Submit target
                    </span>

                </div>

                <div class="stat">

                    <strong>
                        02
                    </strong>

                    <span>
                        Define scope
                    </span>

                </div>

                <div class="stat">

                    <strong>
                        03
                    </strong>

                    <span>
                        Receive report
                    </span>

                </div>

            </div>

        </div>


        <div class="panel card">

            <div class="status">

                <span class="dot"></span>

                LIVE SYSTEM

            </div>

            <h2>
                Security Assessment Console
            </h2>

            <p class="muted">

                Requests, direct messaging,
                findings and reports in one
                dark cyber dashboard.

            </p>

            <div class="code">

                AUTHORIZATION → REQUIRED
                <br>

                SCOPE → CLIENT DEFINED
                <br>

                SCANNING → MANUAL / AUTHORIZED
                <br>

                REPORT → LIVE PORTAL

            </div>

        </div>

    </div>

</section>


<section
    id="how"
    class="section"
>

    <div class="wrap">

        <h2 class="title">
            How it works
        </h2>

        <p class="sub">
            Simple workflow for authorized reviews.
        </p>

        <div class="cards">

            <div class="panel card">

                <h3>
                    01 · Submit
                </h3>

                <p class="muted">

                    Send your name, email,
                    web name, target and
                    authorized scope.

                </p>

            </div>


            <div class="panel card">

                <h3>
                    02 · Review
                </h3>

                <p class="muted">

                    The request appears in
                    the private admin console.

                </p>

            </div>


            <div class="panel card">

                <h3>
                    03 · Report
                </h3>

                <p class="muted">

                    Published findings become
                    available in the client portal.

                </p>

            </div>

        </div>

    </div>

</section>
'''

    return page(
        "Home",
        body
    )


# ============================================================
# REQUEST
# ============================================================

@app.route(
    "/request",
    methods=["GET", "POST"]
)
def new_request():

    error = ""

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        web_name = request.form.get(
            "web_name",
            ""
        ).strip()

        target = request.form.get(
            "target",
            ""
        ).strip()

        scope = request.form.get(
            "scope",
            ""
        ).strip()

        authorization = request.form.get(
            "authorization"
        )

        if not name:
            error = "Name is required."

        elif "@" not in email:
            error = "Valid email is required."

        elif not web_name:
            error = "Web Name is required."

        elif not valid_target(target):
            error = (
                "Use a valid HTTP or HTTPS target."
            )

        elif not scope:
            error = (
                "Authorized Scope is required."
            )

        elif not authorization:
            error = (
                "Authorization confirmation "
                "is required."
            )

        else:

            token = secrets.token_urlsafe(32)
            stamp = now()

            c = db()

            cur = c.execute(
                """
                INSERT INTO requests(
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
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    token,
                    name,
                    email,
                    web_name,
                    target,
                    scope,
                    "PENDING",
                    stamp,
                    stamp,
                    request.headers.get(
                        "X-Forwarded-For",
                        request.remote_addr or ""
                    )
                )
            )

            rid = cur.lastrowid

            c.commit()
            c.close()

            socketio.emit(
                "request_new",
                {
                    "id": rid,
                    "name": name,
                    "web_name": web_name,
                    "target": target
                },
                room="admin"
            )

            return redirect(
                url_for(
                    "client_status",
                    request_id=rid,
                    token=token
                )
            )

    err = (
        f'<div class="notice error">'
        f'{esc(error)}'
        f'</div>'
        if error
        else ""
    )

    body = f'''
<section class="section">

    <div class="wrap form">

        <div style="margin-bottom:22px">

            <div class="status">

                <span class="dot"></span>

                NEW SECURITY REQUEST

            </div>

            <h1
                class="title"
                style="font-size:42px"
            >
                Start an authorized assessment
            </h1>

            <p class="sub">

                Enter the website details
                and define the exact
                authorized scope.

            </p>

        </div>


        <div class="panel card">

            {err}

            <form
                method="POST"
                action="/request"
            >

                <div class="grid">

                    <div class="field">

                        <label>
                            Your Name
                        </label>

                        <input
                            name="name"
                            type="text"
                            placeholder="Matia Becolli"
                            autocomplete="name"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Your Email
                        </label>

                        <input
                            name="email"
                            type="email"
                            placeholder="you@example.com"
                            autocomplete="email"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Web Name
                        </label>

                        <input
                            name="web_name"
                            type="text"
                            placeholder="My Website"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Web Target
                        </label>

                        <input
                            name="target"
                            type="url"
                            placeholder="https://example.com"
                            required
                        >

                    </div>


                    <div class="field full">

                        <label>
                            Authorized Scope
                        </label>

                        <textarea
                            name="scope"
                            placeholder="Example: public website only. No destructive testing."
                            required
                        ></textarea>

                    </div>


                    <div class="field full">

                        <label class="check">

                            <input
                                type="checkbox"
                                name="authorization"
                                required
                            >

                            <span>

                                I confirm that I own
                                this website or have
                                explicit authorization
                                to request this security
                                assessment.

                            </span>

                        </label>

                    </div>


                    <div class="field full">

                        <button
                            class="btn primary"
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
'''

    return page(
        "New Request",
        body
    )


# ============================================================
# CLIENT STATUS
# ============================================================

@app.route(
    "/status/<int:request_id>"
)
def client_status(request_id):

    token = request.args.get(
        "token",
        ""
    )

    if not authorized(
        request_id,
        token
    ):
        abort(403)

    item = get_request(
        request_id
    )

    c = db()

    messages = c.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = c.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    c.close()

    status = item["status"].lower()

    ip = (
        resolve_target(
            item["target"]
        )
        or "N/A"
    )

    script = f'''
const s = io();

s.on(
    "connect",
    () => {{
        s.emit(
            "join_request",
            {{
                request_id:{request_id}
            }}
        );
    }}
);

s.on(
    "new_message",
    d => {{

        if (
            d.request_id !==
            {request_id}
        ) return;

        document
            .getElementById("chat")
            .insertAdjacentHTML(
                "beforeend",
                `
                <div class="msg admin">

                    <div class="who">
                        ${{safe(d.sender)}}
                    </div>

                    <div>
                        ${{safe(d.message)}}
                    </div>

                    <div class="time">
                        ${{safe(d.created_at)}}
                    </div>

                </div>
                `
            );

        document
            .getElementById("chat")
            .scrollTop = 999999;

    }}
);


s.on(
    "finding_new",
    d => {{

        if (
            d.request_id ===
            {request_id}
        ) {{
            location.reload();
        }}

    }}
);


function safe(x) {{

    return String(x)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );
}}
'''

    body = f'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    CLIENT SECURITY PORTAL

                </div>

                <h1 class="title">

                    {esc(item["web_name"])}

                </h1>

                <p class="muted">

                    Request #{item["id"]}
                    ·
                    {esc(item["target"])}

                </p>

            </div>


            <span
                class="badge {status}"
            >
                {esc(item["status"])}
            </span>

        </div>


        <div
            class="kpis"
            style="margin-bottom:18px"
        >

            <div class="kpi panel">

                <strong>
                    #{item["id"]}
                </strong>

                <span>
                    Request ID
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {len(findings)}
                </strong>

                <span>
                    Findings
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {esc(ip)}
                </strong>

                <span>
                    Resolved IP
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    LIVE
                </strong>

                <span>
                    Portal
                </span>

            </div>

        </div>


        <div class="two">

            <div>

                <div
                    class="panel card"
                    style="margin-bottom:18px"
                >

                    <h3>
                        Assessment Details
                    </h3>

                    <p class="muted">

                        <b>Name:</b>
                        {esc(item["name"])}

                    </p>

                    <p class="muted">

                        <b>Email:</b>
                        {esc(item["email"])}

                    </p>

                    <p class="muted">

                        <b>Web Name:</b>
                        {esc(item["web_name"])}

                    </p>

                    <p class="muted">

                        <b>Target:</b>
                        {esc(item["target"])}

                    </p>

                    <p class="muted">

                        <b>Scope:</b>

                        <br>

                        {esc(item["scope"])}

                    </p>

                    <a
                        class="btn dark"
                        href="/report/{request_id}?token={esc(token)}"
                    >
                        View Full Report →
                    </a>

                </div>


                <h2 class="title">
                    Security Findings
                </h2>

                {finding_cards(findings)}

            </div>


            <div class="panel chat">

                <div
                    class="card"
                    style="
                    border:0;
                    border-bottom:
                        1px solid var(--border);
                    border-radius:
                        20px 20px 0 0
                    "
                >

                    <h3
                        style="margin:0"
                    >
                        Live Analyst Chat
                    </h3>

                    <p class="muted">
                        Messages appear instantly.
                    </p>

                </div>


                <div
                    class="chatbox"
                    id="chat"
                >
                    {message_html(messages)}
                </div>


                <form
                    class="chatform"
                    method="POST"
                    action="/status/{request_id}/message?token={esc(token)}"
                >

                    <input
                        name="message"
                        placeholder="Type a message..."
                        required
                    >

                    <button
                        class="btn primary"
                    >
                        Send
                    </button>

                </form>

            </div>

        </div>

    </div>

</section>
'''

    return page(
        f"Client Portal #{request_id}",
        body,
        script
    )


@app.route(
    "/status/<int:request_id>/message",
    methods=["POST"]
)
def client_message(request_id):

    token = request.args.get(
        "token",
        ""
    )

    if not authorized(
        request_id,
        token
    ):
        abort(403)

    msg = request.form.get(
        "message",
        ""
    ).strip()

    if msg:

        stamp = now()

        c = db()

        c.execute(
            """
            INSERT INTO messages(
                request_id,
                sender,
                message,
                created_at
            )
            VALUES(?,?,?,?)
            """,
            (
                request_id,
                "client",
                msg,
                stamp
            )
        )

        c.commit()
        c.close()

        socketio.emit(
            "new_message",
            {
                "request_id":
                    request_id,
                "sender":
                    "client",
                "message":
                    msg,
                "created_at":
                    stamp
            },
            room=f"request_{request_id}"
        )

        socketio.emit(
            "admin_message",
            {
                "request_id":
                    request_id
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

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    error = ""

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if (
            email == ADMIN_EMAIL
            and password == ADMIN_PASSWORD
        ):

            session[
                "admin_logged_in"
            ] = True

            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )

        error = (
            "Invalid admin credentials."
        )

    err = (
        f'''
        <div class="notice error">
            {esc(error)}
        </div>
        '''
        if error
        else ""
    )

    body = f'''
<section class="login">

    <div class="status">

        <span class="dot"></span>

        PRIVATE ADMIN ACCESS

    </div>


    <div class="panel">

        <h1 style="margin-top:0">
            Admin Console
        </h1>

        <p class="muted">

            Only the authorized
            admin account can enter.

        </p>

        {err}


        <form method="POST">

            <div
                class="field"
                style="margin-bottom:15px"
            >

                <label>
                    Admin Email
                </label>

                <input
                    name="email"
                    type="email"
                    value="{esc(ADMIN_EMAIL)}"
                    autocomplete="username"
                    required
                >

            </div>


            <div
                class="field"
                style="margin-bottom:20px"
            >

                <label>
                    Password
                </label>

                <input
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    placeholder="Your Render admin password"
                    required
                >

            </div>


            <button
                class="btn primary"
                style="width:100%"
            >
                ENTER ADMIN CONSOLE
            </button>

        </form>

    </div>

</section>
'''

    return page(
        "Admin Login",
        body
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    c = db()

    rows = c.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    total = len(rows)

    pending = sum(
        r["status"] == "PENDING"
        for r in rows
    )

    progress = sum(
        r["status"] == "IN PROGRESS"
        for r in rows
    )

    finding_count = c.execute(
        "SELECT COUNT(*) n FROM findings"
    ).fetchone()["n"]

    c.close()

    trs = []

    for r in rows:

        st = r["status"].lower()

        trs.append(
            f'''
            <tr>

                <td>
                    #{r["id"]}
                </td>

                <td>

                    <b>
                        {esc(r["web_name"])}
                    </b>

                    <br>

                    <span class="muted">
                        {esc(r["name"])}
                    </span>

                </td>

                <td>
                    {esc(r["email"])}
                </td>

                <td>
                    {esc(r["target"])}
                </td>

                <td>

                    <span
                        class="badge {st}"
                    >
                        {esc(r["status"])}
                    </span>

                </td>

                <td>

                    <a
                        class="btn dark"
                        href="/admin/request/{r["id"]}"
                    >
                        Open
                    </a>

                </td>

            </tr>
            '''
        )

    script = '''
const s = io();

s.on(
    "connect",
    () => s.emit("join_admin")
);

s.on(
    "request_new",
    () => location.reload()
);
'''

    body = f'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    ADMIN CONSOLE ONLINE

                </div>

                <h1 class="title">
                    Security Operations
                </h1>

                <p class="sub">
                    Requests, clients, chat and findings.
                </p>

            </div>


            <a
                class="btn red"
                href="/admin/logout"
            >
                Logout
            </a>

        </div>


        <div
            class="kpis"
            style="margin-bottom:18px"
        >

            <div class="kpi panel">

                <strong>
                    {total}
                </strong>

                <span>
                    Total requests
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {pending}
                </strong>

                <span>
                    Pending
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {progress}
                </strong>

                <span>
                    In progress
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {finding_count}
                </strong>

                <span>
                    Findings
                </span>

            </div>

        </div>


        <div class="panel table">

            <table>

                <thead>

                    <tr>

                        <th>
                            ID
                        </th>

                        <th>
                            Website
                        </th>

                        <th>
                            Email
                        </th>

                        <th>
                            Target
                        </th>

                        <th>
                            Status
                        </th>

                        <th>
                            Action
                        </th>

                    </tr>

                </thead>


                <tbody>

                    {
                        "".join(trs)
                        or
                        '''
                        <tr>

                            <td colspan="6">

                                <div class="empty">
                                    No requests yet.
                                </div>

                            </td>

                        </tr>
                        '''
                    }

                </tbody>

            </table>

        </div>

    </div>

</section>
'''

    return page(
        "Admin Console",
        body,
        script
    )


# ============================================================
# ADMIN REQUEST
# ============================================================

@app.route(
    "/admin/request/<int:request_id>",
    methods=["GET", "POST"]
)
@admin_required
def admin_request(request_id):

    item = get_request(
        request_id
    )

    if not item:
        abort(404)

    if request.method == "POST":

        status = request.form.get(
            "status",
            ""
        )

        if status in {
            "PENDING",
            "ACCEPTED",
            "IN PROGRESS",
            "COMPLETED",
            "DECLINED"
        }:

            c = db()

            c.execute(
                """
                UPDATE requests
                SET status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    status,
                    now(),
                    request_id
                )
            )

            c.commit()
            c.close()

            socketio.emit(
                "status_update",
                {
                    "request_id":
                        request_id,
                    "status":
                        status
                },
                room=f"request_{request_id}"
            )

            item = get_request(
                request_id
            )

    c = db()

    messages = c.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (request_id,)
    ).fetchall()

    findings = c.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    c.close()

    selected = lambda x: (
        "selected"
        if item["status"] == x
        else ""
    )

    script = f'''
const s = io();

s.on(
    "connect",
    () => {{

        s.emit("join_admin");

        s.emit(
            "join_request",
            {{
                request_id:{request_id}
            }}
        );

    }}
);


s.on(
    "new_message",
    d => {{

        if (
            d.request_id !==
            {request_id}
        ) return;

        document
            .getElementById("achat")
            .insertAdjacentHTML(
                "beforeend",
                `
                <div class="msg client">

                    <div class="who">
                        ${{d.sender}}
                    </div>

                    <div>
                        ${{d.message}}
                    </div>

                    <div class="time">
                        ${{d.created_at}}
                    </div>

                </div>
                `
            );

        document
            .getElementById("achat")
            .scrollTop = 999999;

    }}
);
'''

    body = f'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    REQUEST #{request_id}

                </div>

                <h1 class="title">
                    {esc(item["web_name"])}
                </h1>

                <p class="muted">
                    {esc(item["target"])}
                </p>

            </div>


            <a
                class="btn dark"
                href="/admin"
            >
                ← Dashboard
            </a>

        </div>


        <div class="two">

            <div>

                <div
                    class="panel card"
                    style="margin-bottom:18px"
                >

                    <h3>
                        Client Information
                    </h3>

                    <p class="muted">

                        <b>
                            Name:
                        </b>

                        {esc(item["name"])}

                    </p>


                    <p class="muted">

                        <b>
                            Email:
                        </b>

                        {esc(item["email"])}

                    </p>


                    <p class="muted">

                        <b>
                            Web Name:
                        </b>

                        {esc(item["web_name"])}

                    </p>


                    <p class="muted">

                        <b>
                            Target:
                        </b>

                        {esc(item["target"])}

                    </p>


                    <p class="muted">

                        <b>
                            Scope:
                        </b>

                        <br>

                        {esc(item["scope"])}

                    </p>


                    <p class="muted">

                        <b>
                            DNS:
                        </b>

                        {esc(
                            resolve_target(
                                item["target"]
                            )
                            or
                            "Not resolved"
                        )}

                    </p>

                </div>


                <div
                    class="panel card"
                    style="margin-bottom:18px"
                >

                    <h3>
                        Change Status
                    </h3>


                    <form method="POST">

                        <select
                            name="status"
                        >

                            <option
                                value="PENDING"
                                {selected("PENDING")}
                            >
                                PENDING
                            </option>

                            <option
                                value="ACCEPTED"
                                {selected("ACCEPTED")}
                            >
                                ACCEPTED
                            </option>

                            <option
                                value="IN PROGRESS"
                                {selected("IN PROGRESS")}
                            >
                                IN PROGRESS
                            </option>

                            <option
                                value="COMPLETED"
                                {selected("COMPLETED")}
                            >
                                COMPLETED
                            </option>

                            <option
                                value="DECLINED"
                                {selected("DECLINED")}
                            >
                                DECLINED
                            </option>

                        </select>


                        <button
                            class="btn primary"
                            style="margin-top:10px"
                        >
                            UPDATE STATUS
                        </button>

                    </form>

                </div>


                <h2 class="title">
                    Findings
                </h2>

                {finding_cards(findings)}

            </div>


            <div class="panel chat">

                <div class="card">

                    <h3 style="margin:0">
                        Client Chat
                    </h3>

                    <p class="muted">
                        Live communication.
                    </p>

                </div>


                <div
                    class="chatbox"
                    id="achat"
                >
                    {message_html(messages)}
                </div>


                <form
                    class="chatform"
                    method="POST"
                    action="/admin/request/{request_id}/message"
                >

                    <input
                        name="message"
                        placeholder="Reply to client..."
                        required
                    >

                    <button
                        class="btn primary"
                    >
                        Send
                    </button>

                </form>

            </div>

        </div>


        <div
            class="panel card"
            style="margin-top:18px"
        >

            <h2 style="margin-top:0">
                Publish Finding
            </h2>


            <form
                method="POST"
                action="/admin/request/{request_id}/finding"
            >

                <div class="grid">

                    <div class="field">

                        <label>
                            Title
                        </label>

                        <input
                            name="title"
                            placeholder="Information Disclosure"
                            required
                        >

                    </div>


                    <div class="field">

                        <label>
                            Severity
                        </label>

                        <select
                            name="severity"
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

                    </div>


                    <div class="field full">

                        <label>
                            Description
                        </label>

                        <textarea
                            name="description"
                            required
                        ></textarea>

                    </div>


                    <div class="field full">

                        <label>
                            Evidence
                        </label>

                        <textarea
                            name="evidence"
                            required
                        ></textarea>

                    </div>


                    <div class="field full">

                        <label>
                            Recommendation
                        </label>

                        <textarea
                            name="recommendation"
                            required
                        ></textarea>

                    </div>


                    <div class="field full">

                        <button
                            class="btn green"
                        >
                            PUBLISH FINDING
                        </button>

                    </div>

                </div>

            </form>

        </div>


        <div style="margin-top:18px">

            <a
                class="btn dark"
                href="/admin/report/{request_id}"
            >
                View Full Report →
            </a>

        </div>

    </div>

</section>
'''

    return page(
        f"Request #{request_id}",
        body,
        script
    )


# ============================================================
# ADMIN MESSAGE
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/message",
    methods=["POST"]
)
@admin_required
def admin_message(request_id):

    msg = request.form.get(
        "message",
        ""
    ).strip()

    if msg:

        stamp = now()

        c = db()

        c.execute(
            """
            INSERT INTO messages(
                request_id,
                sender,
                message,
                created_at
            )
            VALUES(?,?,?,?)
            """,
            (
                request_id,
                "admin",
                msg,
                stamp
            )
        )

        c.commit()
        c.close()

        socketio.emit(
            "new_message",
            {
                "request_id":
                    request_id,
                "sender":
                    "admin",
                "message":
                    msg,
                "created_at":
                    stamp
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
# ADD FINDING
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/finding",
    methods=["POST"]
)
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

    if (
        severity not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        }
        or
        not all([
            title,
            description,
            evidence,
            recommendation
        ])
    ):
        abort(400)

    c = db()

    cur = c.execute(
        """
        INSERT INTO findings(
            request_id,
            title,
            severity,
            description,
            evidence,
            recommendation,
            created_at
        )
        VALUES(?,?,?,?,?,?,?)
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

    c.commit()

    fid = cur.lastrowid

    c.close()

    socketio.emit(
        "finding_new",
        {
            "request_id":
                request_id,
            "finding_id":
                fid,
            "title":
                title,
            "severity":
                severity
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

@app.route(
    "/admin/report/<int:request_id>"
)
@admin_required
def admin_report(request_id):

    item = get_request(
        request_id
    )

    if not item:
        abort(404)

    c = db()

    findings = c.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    c.close()

    body = f'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    SECURITY REPORT

                </div>

                <h1 class="title">
                    {esc(item["web_name"])}
                </h1>

                <p class="muted">
                    {esc(item["target"])}
                </p>

            </div>


            <a
                class="btn dark"
                href="/admin/request/{request_id}"
            >
                ← Back
            </a>

        </div>


        <div
            class="panel card"
            style="margin-bottom:18px"
        >

            <h3>
                Assessment Overview
            </h3>

            <p class="muted">

                <b>
                    Client:
                </b>

                {esc(item["name"])}

            </p>

            <p class="muted">

                <b>
                    Email:
                </b>

                {esc(item["email"])}

            </p>

            <p class="muted">

                <b>
                    Target:
                </b>

                {esc(item["target"])}

            </p>

            <p class="muted">

                <b>
                    Scope:
                </b>

                <br>

                {esc(item["scope"])}

            </p>

            <p class="muted">

                <b>
                    Status:
                </b>

                {esc(item["status"])}

            </p>

        </div>


        <h2 class="title">
            Findings
        </h2>

        {finding_cards(findings)}

    </div>

</section>
'''

    return page(
        f"Report #{request_id}",
        body
    )


# ============================================================
# CLIENT REPORT
# ============================================================

@app.route(
    "/report/<int:request_id>"
)
def client_report(request_id):

    token = request.args.get(
        "token",
        ""
    )

    if not authorized(
        request_id,
        token
    ):
        abort(403)

    item = get_request(
        request_id
    )

    c = db()

    findings = c.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    c.close()

    body = f'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    PRIVATE SECURITY REPORT

                </div>

                <h1 class="title">
                    {esc(item["web_name"])}
                </h1>

                <p class="muted">
                    {esc(item["target"])}
                </p>

            </div>


            <span
                class="badge
                {item["status"].lower()}"
            >
                {esc(item["status"])}
            </span>

        </div>


        <div
            class="panel card"
            style="margin-bottom:18px"
        >

            <h3>
                Executive Summary
            </h3>

            <p class="muted">

                This report contains findings
                published by the assessment
                administrator and is limited
                to the authorized scope supplied
                with the request.

            </p>

        </div>


        <h2 class="title">
            Security Findings
        </h2>

        {finding_cards(findings)}


        <a
            class="btn dark"
            href="/status/{request_id}?token={esc(token)}"
        >
            ← Back to Portal
        </a>

    </div>

</section>
'''

    return page(
        f"Client Report #{request_id}",
        body
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/admin/logout"
)
def admin_logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# ERRORS
# ============================================================

@app.errorhandler(403)
def forbidden(_):

    return page(
        "Access Denied",
        '''
        <section class="section">

            <div class="wrap">

                <div
                    class="panel card"
                    style="text-align:center"
                >

                    <div style="font-size:55px">
                        🔒
                    </div>

                    <h1>
                        Access denied
                    </h1>

                    <p class="muted">
                        This private portal link is invalid.
                    </p>

                    <a
                        class="btn primary"
                        href="/"
                    >
                        Return Home
                    </a>

                </div>

            </div>

        </section>
        '''
    ), 403


@app.errorhandler(404)
def not_found(_):

    return page(
        "Not Found",
        '''
        <section class="section">

            <div class="wrap">

                <div
                    class="panel card"
                    style="text-align:center"
                >

                    <div style="font-size:55px">
                        🛰️
                    </div>

                    <h1>
                        Page not found
                    </h1>

                    <a
                        class="btn primary"
                        href="/"
                    >
                        Return Home
                    </a>

                </div>

            </div>

        </section>
        '''
    ), 404


# ============================================================
# START
# ============================================================

init_db()

if __name__ == "__main__":

    print(
        f"{APP_NAME} starting on port {PORT}"
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=PORT,
        allow_unsafe_werkzeug=True
    )
