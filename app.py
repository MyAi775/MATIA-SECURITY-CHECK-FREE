import os
import html
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    abort,
    jsonify,
    render_template_string,
)

APP_NAME = "MATIA // SECURITY CHECK"

ADMIN_EMAIL = os.getenv(
    "MATIA_ADMIN_EMAIL",
    "kleimatia1@gmail.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv(
    "MATIA_ADMIN_PASSWORD",
    ""
)

SECRET_KEY = os.getenv(
    "MATIA_SECRET_KEY",
    ""
)

DB_FILE = os.getenv(
    "MATIA_DB_FILE",
    "matia_security.db"
)

PORT = int(
    os.getenv(
        "PORT",
        "5000"
    )
)

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "MATIA_ADMIN_PASSWORD is missing."
    )

if not SECRET_KEY:
    raise RuntimeError(
        "MATIA_SECRET_KEY is missing."
    )


app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv(
            "COOKIE_SECURE",
            "true"
        ).lower() == "true"
    ),
)


# ============================================================
# CSS
# ============================================================

CSS = r'''
:root{
    --bg:#05070b;
    --panel:#0c121b;
    --panel2:#111927;
    --border:#202c3f;
    --text:#eef4ff;
    --muted:#91a3bb;
    --accent:#6d7cff;
    --cyan:#00e5ff;
    --green:#27e99a;
    --red:#ff506a;
    --yellow:#ffc857;
    --shadow:0 24px 80px rgba(0,0,0,.35);
}

*{
    box-sizing:border-box;
}

html{
    scroll-behavior:smooth;
}

body{
    margin:0;
    min-height:100vh;
    color:var(--text);
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(109,124,255,.17),
            transparent 28%
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
}

a{
    color:inherit;
    text-decoration:none;
}

button,
input,
textarea,
select{
    font:inherit;
}

.wrap{
    width:min(1180px,92%);
    margin:auto;
}

.top{
    position:sticky;
    top:0;
    z-index:50;
    background:rgba(4,6,10,.78);
    backdrop-filter:blur(16px);
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
    gap:11px;
    font-weight:950;
    letter-spacing:.7px;
}

.logo{
    width:39px;
    height:39px;
    display:grid;
    place-items:center;
    border-radius:12px;
    background:
        linear-gradient(
            135deg,
            var(--accent),
            var(--cyan)
        );
    color:#03060b;
    box-shadow:
        0 0 32px
        rgba(109,124,255,.35);
}

.brand small{
    display:block;
    color:var(--muted);
    font-size:9px;
    letter-spacing:1.7px;
    margin-top:2px;
}

.links{
    display:flex;
    gap:5px;
}

.links a{
    padding:10px 12px;
    color:var(--muted);
    border-radius:10px;
}

.links a:hover{
    background:rgba(255,255,255,.05);
    color:var(--text);
}

.hero{
    padding:90px 0 50px;
}

.hero-grid,
.two{
    display:grid;
    grid-template-columns:1.12fr .88fr;
    gap:20px;
}

.status{
    display:flex;
    align-items:center;
    gap:9px;
    color:var(--green);
    font-size:12px;
    font-weight:850;
    letter-spacing:.5px;
}

.dot{
    width:8px;
    height:8px;
    border-radius:50%;
    background:var(--green);
    box-shadow:0 0 16px var(--green);
}

.hero h1{
    font-size:clamp(46px,7vw,86px);
    line-height:.93;
    letter-spacing:-4px;
    margin:12px 0 20px;
}

.grad{
    background:
        linear-gradient(
            90deg,
            #fff,
            var(--cyan),
            #99a0ff
        );
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent;
}

.muted{
    color:var(--muted);
    line-height:1.72;
}

.panel{
    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.035),
            rgba(255,255,255,.012)
        ),
        var(--panel);

    border:1px solid var(--border);
    border-radius:22px;
    box-shadow:var(--shadow);
}

.card{
    padding:22px;
}

.section{
    padding:34px 0;
}

.title{
    margin:0 0 8px;
    font-size:32px;
}

.sub{
    margin:0 0 22px;
    color:var(--muted);
}

.stats,
.kpis,
.cards{
    display:grid;
    gap:12px;
}

.stats{
    grid-template-columns:repeat(3,1fr);
    margin-top:24px;
}

.kpis{
    grid-template-columns:repeat(4,1fr);
}

.cards{
    grid-template-columns:repeat(3,1fr);
}

.stat,
.kpi{
    padding:18px;
    border:1px solid var(--border);
    border-radius:15px;
    background:rgba(255,255,255,.02);
}

.stat strong,
.kpi strong{
    display:block;
    font-size:25px;
    margin-bottom:4px;
}

.stat span,
.kpi span{
    font-size:12px;
    color:var(--muted);
}

.form{
    width:min(900px,100%);
    margin:32px auto 70px;
}

.grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:16px;
}

.field{
    display:flex;
    flex-direction:column;
    gap:8px;
}

.full{
    grid-column:1/-1;
}

label{
    font-size:13px;
    font-weight:850;
    color:#cad6e7;
}

input,
textarea,
select{
    width:100%;
    padding:14px 15px;
    border:1px solid var(--border);
    border-radius:13px;
    background:#080c12;
    color:var(--text);
    outline:none;
    font:inherit;
}

input:focus,
textarea:focus,
select:focus{
    border-color:var(--accent);
    box-shadow:
        0 0 0 3px
        rgba(109,124,255,.12);
}

input[readonly]{
    opacity:.9;
}

textarea{
    min-height:130px;
    resize:vertical;
}

.check{
    display:flex;
    align-items:flex-start;
    gap:9px;
    color:var(--muted);
    font-size:13px;
    line-height:1.6;
}

.check input{
    width:auto;
    margin-top:4px;
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:8px;
}

.btn{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:8px;
    padding:13px 17px;
    border:0;
    border-radius:12px;
    color:#fff;
    font-weight:900;
    cursor:pointer;
    transition:.18s;
}

.btn:hover{
    transform:translateY(-1px);
}

.primary{
    background:
        linear-gradient(
            135deg,
            var(--accent),
            #8e61ff
        );
    box-shadow:
        0 14px 30px
        rgba(109,124,255,.20);
}

.dark{
    background:#111824;
    border:1px solid var(--border);
}

.green{
    background:
        linear-gradient(
            135deg,
            #1cca7b,
            #0ca45d
        );
}

.red{
    background:
        linear-gradient(
            135deg,
            #ff536a,
            #e33f57
        );
}

.yellow{
    background:
        linear-gradient(
            135deg,
            #c99a2c,
            #f2bd43
        );
    color:#111;
}

.notice{
    padding:13px 15px;
    margin-bottom:15px;
    border:1px solid var(--border);
    border-radius:12px;
}

.error{
    color:#ffbac4;
    background:rgba(255,80,105,.09);
    border-color:rgba(255,80,105,.23);
}

.success{
    color:#9df9ce;
    background:rgba(36,233,154,.08);
    border-color:rgba(36,233,154,.22);
}

.table{
    overflow:auto;
}

.table table{
    width:100%;
    border-collapse:collapse;
}

.table th,
.table td{
    padding:13px;
    border-bottom:1px solid var(--border);
    text-align:left;
    white-space:nowrap;
}

.table th{
    color:#93a5bd;
    font-size:11px;
    text-transform:uppercase;
}

.badge{
    display:inline-flex;
    padding:6px 10px;
    border-radius:999px;
    font-size:11px;
    font-weight:900;
    border:1px solid transparent;
}

.pending{
    color:#ffd978;
    background:rgba(255,200,87,.08);
    border-color:rgba(255,200,87,.2);
}

.accepted{
    color:#80f1b8;
    background:rgba(36,233,154,.08);
    border-color:rgba(36,233,154,.2);
}

.progress{
    color:#79efff;
    background:rgba(0,229,255,.08);
    border-color:rgba(0,229,255,.2);
}

.completed{
    color:#80f1b8;
    background:rgba(36,233,154,.08);
    border-color:rgba(36,233,154,.2);
}

.declined{
    color:#ff9eac;
    background:rgba(255,80,105,.08);
    border-color:rgba(255,80,105,.2);
}

.chat{
    display:flex;
    flex-direction:column;
    min-height:540px;
}

.chatbox{
    flex:1;
    max-height:520px;
    overflow:auto;
    padding:18px;
    display:flex;
    flex-direction:column;
    gap:10px;
}

.msg{
    max-width:82%;
    padding:11px 13px;
    border:1px solid var(--border);
    border-radius:14px;
    background:#0a0f16;
}

.msg.admin{
    align-self:flex-end;
    background:rgba(109,124,255,.12);
    border-color:rgba(109,124,255,.22);
}

.msg.client{
    align-self:flex-start;
}

.msg.system{
    align-self:center;
    max-width:92%;
    background:rgba(0,229,255,.06);
    border-color:rgba(0,229,255,.14);
    text-align:center;
}

.who{
    margin-bottom:5px;
    color:var(--muted);
    font-size:10px;
    font-weight:900;
    letter-spacing:.8px;
    text-transform:uppercase;
}

.time{
    margin-top:6px;
    color:#69788d;
    font-size:10px;
}

.chatform{
    display:flex;
    gap:9px;
    padding:13px;
    border-top:1px solid var(--border);
}

.chatform input{
    flex:1;
}

.finding{
    padding:20px;
    margin-bottom:12px;
}

.finding h3{
    margin:4px 0 8px;
}

.sev{
    font-weight:900;
}

.sev.critical{
    color:#ff6176;
}

.sev.high{
    color:#ff8d67;
}

.sev.medium{
    color:#ffd36d;
}

.sev.low{
    color:#5fe6a4;
}

.sev.info{
    color:#77ddff;
}

.head{
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    gap:15px;
    margin-bottom:20px;
}

.empty{
    text-align:center;
    padding:30px;
    color:var(--muted);
}

.footer{
    text-align:center;
    padding:52px 0;
    color:#66768d;
    font-size:12px;
}

.login{
    width:min(480px,92%);
    margin:82px auto;
}

.login .panel{
    padding:28px;
}

.client-item{
    padding:18px;
    border-bottom:1px solid var(--border);
    display:flex;
    justify-content:space-between;
    gap:20px;
    align-items:center;
}

.client-item:last-child{
    border-bottom:0;
}

.client-main{
    min-width:0;
}

.client-name{
    font-size:17px;
    font-weight:900;
}

.client-target{
    font-size:12px;
    color:var(--muted);
    overflow:hidden;
    text-overflow:ellipsis;
}

.client-meta{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
    margin-top:8px;
}

@media(max-width:900px){

    .hero-grid,
    .two{
        grid-template-columns:1fr;
    }

    .cards{
        grid-template-columns:1fr;
    }

    .kpis{
        grid-template-columns:repeat(2,1fr);
    }

    .client-item{
        align-items:flex-start;
        flex-direction:column;
    }
}

@media(max-width:650px){

    .links{
        display:none;
    }

    .grid{
        grid-template-columns:1fr;
    }

    .full{
        grid-column:auto;
    }

    .stats{
        grid-template-columns:1fr;
    }

    .hero h1{
        letter-spacing:-2px;
    }

    .kpis{
        grid-template-columns:1fr 1fr;
    }
}
'''


PAGE = r'''
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    {{ title|e }} — {{ app_name|e }}
</title>

<style>
{{ css|safe }}
</style>

</head>

<body>

<div class="top">

    <div class="wrap nav">

        <a
            class="brand"
            href="{{ url_for('home') }}"
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
{{ body|safe }}
</main>

<div class="footer">
    MATIA // SECURITY CHECK · Authorized Security Assessment Portal
</div>

<script>
{{ script|safe }}
</script>

</body>

</html>
'''


def render_page(
    title,
    body,
    script=""
):
    return render_template_string(
        PAGE,
        title=title,
        app_name=APP_NAME,
        css=CSS,
        body=body,
        script=script,
    )


def db():

    connection = sqlite3.connect(
        DB_FILE,
        timeout=20
    )

    connection.row_factory = sqlite3.Row

    return connection


def now():
    return datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def esc(value):
    return html.escape(
        str(value or ""),
        quote=True
    )


def valid_target(target):

    try:

        parsed = urlparse(
            target.strip()
        )

        return (
            parsed.scheme
            in (
                "http",
                "https"
            )
            and bool(
                parsed.netloc
            )
        )

    except Exception:

        return False


def get_request(request_id):

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (
            request_id,
        )
    ).fetchone()

    connection.close()

    return row


def client_authorized(
    request_id,
    token
):

    if not token:
        return False

    connection = db()

    row = connection.execute(
        """
        SELECT id
        FROM requests
        WHERE id=?
        AND client_token=?
        """,
        (
            request_id,
            token
        )
    ).fetchone()

    connection.close()

    return row is not None


def admin_required(
    function
):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get(
            "admin_logged_in"
        ):
            return redirect(
                url_for(
                    "admin_login"
                )
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


def init_db():

    connection = db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS requests(
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
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
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

    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(requests)"
        ).fetchall()
    }

    if "client_token" not in columns:

        connection.execute(
            """
            ALTER TABLE requests
            ADD COLUMN client_token TEXT
            """
        )

    if "web_name" not in columns:

        connection.execute(
            """
            ALTER TABLE requests
            ADD COLUMN web_name TEXT
            """
        )

    connection.commit()
    connection.close()


def render_messages(rows):

    if not rows:

        return (
            '<div class="empty">'
            'No messages yet.'
            '</div>'
        )

    output = []

    for row in rows:

        sender = row["sender"]

        if sender not in (
            "admin",
            "client",
            "system"
        ):
            sender = "system"

        output.append(
            '<div class="msg '
            + sender
            + '">'

            '<div class="who">'
            + esc(row["sender"])
            + '</div>'

            '<div>'
            + esc(row["message"])
            + '</div>'

            '<div class="time">'
            + esc(row["created_at"])
            + '</div>'

            '</div>'
        )

    return "".join(output)


def render_findings(rows):

    if not rows:

        return (
            '<div class="panel empty">'
            'No findings published yet.'
            '</div>'
        )

    output = []

    for row in rows:

        severity = (
            row["severity"]
            or "INFO"
        ).lower()

        output.append(
            '<div class="panel finding">'

            '<div class="sev '
            + esc(severity)
            + '">'
            + esc(row["severity"])
            + '</div>'

            '<h3>'
            + esc(row["title"])
            + '</h3>'

            '<p class="muted">'
            '<b>Description</b><br>'
            + esc(row["description"])
            + '</p>'

            '<p class="muted">'
            '<b>Evidence</b><br>'
            + esc(row["evidence"])
            + '</p>'

            '<p class="muted">'
            '<b>Recommendation</b><br>'
            + esc(row["recommendation"])
            + '</p>'

            '</div>'
        )

    return "".join(output)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    body = r'''
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

                MATIA // SECURITY CHECK is a
                modern portal for authorized
                website security assessments,
                client communication and
                structured reporting.

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
                    <strong>01</strong>
                    <span>Submit target</span>
                </div>

                <div class="stat">
                    <strong>02</strong>
                    <span>Review request</span>
                </div>

                <div class="stat">
                    <strong>03</strong>
                    <span>Receive report</span>
                </div>

            </div>

        </div>

        <div class="panel card">

            <div class="status">
                <span class="dot"></span>
                LIVE SYSTEM
            </div>

            <h2>
                Security Operations Portal
            </h2>

            <p class="muted">

                Client queue,
                accept/decline workflow,
                private chat,
                findings and reports.

            </p>

            <div class="code">

                AUTHORIZATION → REQUIRED
                <br>
                SCOPE → CLIENT DEFINED
                <br>
                CHAT → AFTER ACCEPT
                <br>
                REPORT → PRIVATE PORTAL
                <br>
                ENGINE → FLASK + GUNICORN

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
            A simple authorized workflow.
        </p>

        <div class="cards">

            <div class="panel card">

                <h3>
                    01 · Submit
                </h3>

                <p class="muted">

                    Client enters name, email,
                    web name, target and
                    authorized scope.

                </p>

            </div>

            <div class="panel card">

                <h3>
                    02 · Decision
                </h3>

                <p class="muted">

                    You open one client and
                    choose ACCEPT or DECLINE.

                </p>

            </div>

            <div class="panel card">

                <h3>
                    03 · Chat & Report
                </h3>

                <p class="muted">

                    Accepted clients get
                    the secure chat and
                    report portal.

                </p>

            </div>

        </div>

    </div>

</section>
'''

    return render_page(
        "Home",
        body
    )


# ============================================================
# NEW REQUEST
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

        elif not valid_target(
            target
        ):

            error = (
                "Web Target must be a valid "
                "HTTP or HTTPS URL."
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

            token = (
                secrets.token_urlsafe(32)
            )

            timestamp = now()

            connection = db()

            cursor = connection.execute(
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
                VALUES(
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
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
                    request.remote_addr or ""
                )
            )

            request_id = cursor.lastrowid

            connection.commit()
            connection.close()

            return redirect(
                url_for(
                    "client_status",
                    request_id=request_id,
                    token=token
                )
            )

    body = r'''
<section class="section">

    <div class="wrap form">

        <div
            style="margin-bottom:22px"
        >

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

                Enter the website information
                and define the exact scope.

            </p>

        </div>

        <div class="panel card">

            {% if error %}

            <div class="notice error">
                {{ error|e }}
            </div>

            {% endif %}

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
                            placeholder="Example: public website only. No destructive testing or third-party systems."
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
                                to request this
                                security assessment.

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

    body = render_template_string(
        body,
        error=error
    )

    return render_page(
        "New Request",
        body
    )


# ============================================================
# CLIENT PORTAL
# ============================================================

@app.route(
    "/status/<int:request_id>"
)
def client_status(
    request_id
):

    token = request.args.get(
        "token",
        ""
    )

    if not client_authorized(
        request_id,
        token
    ):
        abort(403)

    item = get_request(
        request_id
    )

    connection = db()

    messages = connection.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (
            request_id,
        )
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (
            request_id,
        )
    ).fetchall()

    connection.close()

    chat_open = item["status"] in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    )

    body = r'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    CLIENT SECURITY PORTAL

                </div>

                <h1 class="title">
                    {{ item.web_name|e }}
                </h1>

                <p class="muted">

                    Request #{{ item.id }}
                    ·
                    {{ item.target|e }}

                </p>

            </div>

            <span
                class="badge
                {{ item.status|lower|replace(' ','-') }}"
            >
                {{ item.status|e }}
            </span>

        </div>

        <div
            class="kpis"
            style="margin-bottom:18px"
        >

            <div class="kpi panel">

                <strong>
                    #{{ item.id }}
                </strong>

                <span>
                    Request ID
                </span>

            </div>

            <div class="kpi panel">

                <strong>
                    {{ findings|length }}
                </strong>

                <span>
                    Findings
                </span>

            </div>

            <div class="kpi panel">

                <strong>
                    {{ "OPEN" if chat_open else "LOCKED" }}
                </strong>

                <span>
                    Client Chat
                </span>

            </div>

            <div class="kpi panel">

                <strong>
                    {{ item.status }}
                </strong>

                <span>
                    Current Status
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

                        <b>
                            Name:
                        </b>

                        {{ item.name|e }}

                    </p>

                    <p class="muted">

                        <b>
                            Email:
                        </b>

                        {{ item.email|e }}

                    </p>

                    <p class="muted">

                        <b>
                            Web Name:
                        </b>

                        {{ item.web_name|e }}

                    </p>

                    <p class="muted">

                        <b>
                            Target:
                        </b>

                        {{ item.target|e }}

                    </p>

                    <p class="muted">

                        <b>
                            Scope:
                        </b>

                        <br>

                        {{ item.scope|e }}

                    </p>

                    <a
                        class="btn dark"
                        href="{{ url_for(
                            'client_report',
                            request_id=item.id,
                            token=token
                        ) }}"
                    >
                        View Full Report →
                    </a>

                </div>

                <h2 class="title">
                    Security Findings
                </h2>

                {{ findings_html|safe }}

            </div>

            <div class="panel chat">

                <div class="card">

                    <h3 style="margin:0">
                        Admin Chat
                    </h3>

                    <p class="muted">

                        {% if chat_open %}

                        Your request has been accepted.
                        Chat is now open.

                        {% else %}

                        🔒 Chat opens after admin approval.

                        {% endif %}

                    </p>

                </div>

                <div class="chatbox">

                    {{ messages_html|safe }}

                </div>

                {% if chat_open %}

                <form
                    class="chatform"
                    method="POST"
                    action="{{ url_for(
                        'client_message',
                        request_id=item.id
                    ) }}?token={{ token|e }}"
                >

                    <input
                        name="message"
                        placeholder="Message admin..."
                        autocomplete="off"
                        required
                    >

                    <button
                        class="btn primary"
                        type="submit"
                    >
                        Send
                    </button>

                </form>

                {% else %}

                <div class="empty">
                    🔒 Waiting for admin approval.
                </div>

                {% endif %}

            </div>

        </div>

    </div>

</section>
'''

    body = render_template_string(
        body,
        item=item,
        token=token,
        findings=findings,
        chat_open=chat_open,
        findings_html=render_findings(
            findings
        ),
        messages_html=render_messages(
            messages
        )
    )

    import json

    script = r'''
async function refreshClient(){

    try{

        const response =
            await fetch(
                "__URL__",
                {
                    cache:"no-store"
                }
            );

        if(!response.ok){
            return;
        }

        const data =
            await response.json();

        if(
            data.updated_at !==
            window.currentUpdated
        ){
            location.reload();
        }

    }catch(error){
        console.log(error);
    }
}

window.currentUpdated =
    __UPDATED__;

setInterval(
    refreshClient,
    2500
);
'''

    script = (
        script
        .replace(
            "__URL__",
            json.dumps(
                url_for(
                    "api_client",
                    request_id=request_id,
                    token=token
                )
            )
        )
        .replace(
            "__UPDATED__",
            json.dumps(
                item["updated_at"]
            )
        )
    )

    return render_page(
        "Client Portal #" + str(request_id),
        body,
        script
    )


@app.route(
    "/api/client/<int:request_id>"
)
def api_client(
    request_id
):

    token = request.args.get(
        "token",
        ""
    )

    if not client_authorized(
        request_id,
        token
    ):
        return jsonify(
            {
                "error":
                    "forbidden"
            }
        ), 403

    item = get_request(
        request_id
    )

    return jsonify(
        {
            "updated_at":
                item["updated_at"],

            "status":
                item["status"]
        }
    )


@app.route(
    "/status/<int:request_id>/message",
    methods=["POST"]
)
def client_message(
    request_id
):

    token = request.args.get(
        "token",
        ""
    )

    if not client_authorized(
        request_id,
        token
    ):
        abort(403)

    item = get_request(
        request_id
    )

    if item["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):
        abort(403)

    message = request.form.get(
        "message",
        ""
    ).strip()

    if message:

        timestamp = now()

        connection = db()

        connection.execute(
            """
            INSERT INTO messages(
                request_id,
                sender,
                message,
                created_at
            )
            VALUES(
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                request_id,
                "client",
                message,
                timestamp
            )
        )

        connection.execute(
            """
            UPDATE requests
            SET updated_at=?
            WHERE id=?
            """,
            (
                timestamp,
                request_id
            )
        )

        connection.commit()
        connection.close()

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
            secrets.compare_digest(
                email,
                ADMIN_EMAIL
            )
            and
            secrets.compare_digest(
                password,
                ADMIN_PASSWORD
            )
        ):

            session.clear()

            session[
                "admin_logged_in"
            ] = True

            session[
                "admin_email"
            ] = ADMIN_EMAIL

            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )

        error = (
            "Invalid admin credentials."
        )

    body = r'''
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

            Your admin email is already
            filled in.

            Save the password in your
            browser once.

        </p>

        {% if error %}

        <div class="notice error">
            {{ error|e }}
        </div>

        {% endif %}

        <form
            method="POST"
            autocomplete="on"
        >

            <div
                class="field"
                style="margin-bottom:15px"
            >

                <label>
                    Admin Email
                </label>

                <input
                    type="email"
                    name="email"
                    value="{{ email|e }}"
                    autocomplete="username"
                    readonly
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
                    type="password"
                    name="password"
                    autocomplete="current-password"
                    placeholder="Your saved admin password"
                    autofocus
                    required
                >

            </div>

            <button
                class="btn primary"
                type="submit"
                style="width:100%"
            >
                ENTER ADMIN CONSOLE →
            </button>

        </form>

    </div>

</section>
'''

    body = render_template_string(
        body,
        email=ADMIN_EMAIL,
        error=error
    )

    return render_page(
        "Admin Login",
        body
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM requests
        ORDER BY
            CASE status
                WHEN 'PENDING' THEN 0
                WHEN 'IN PROGRESS' THEN 1
                WHEN 'ACCEPTED' THEN 2
                WHEN 'COMPLETED' THEN 3
                ELSE 4
            END,
            id DESC
        """
    ).fetchall()

    pending = sum(
        row["status"] == "PENDING"
        for row in rows
    )

    active = sum(
        row["status"]
        in (
            "ACCEPTED",
            "IN PROGRESS"
        )
        for row in rows
    )

    completed = sum(
        row["status"] == "COMPLETED"
        for row in rows
    )

    findings_count = connection.execute(
        """
        SELECT COUNT(*) AS value
        FROM findings
        """
    ).fetchone()["value"]

    connection.close()

    body = r'''
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

                    Open one client at a time.
                    Accept or decline the request;
                    accepted clients unlock chat.

                </p>

            </div>

            <a
                class="btn red"
                href="{{ url_for('admin_logout') }}"
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
                    {{ rows|length }}
                </strong>

                <span>
                    Total Clients
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ pending }}
                </strong>

                <span>
                    Waiting Review
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ active }}
                </strong>

                <span>
                    Active
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ findings_count }}
                </strong>

                <span>
                    Findings
                </span>

            </div>

        </div>


        <div class="panel">

            <div class="card">

                <h2 style="margin:0">
                    Client Queue
                </h2>

                <p class="muted">

                    {{ rows|length }}
                    request(s) in the system.

                </p>

            </div>


            {% if rows %}

                {% for row in rows %}

                <div class="client-item">

                    <div class="client-main">

                        <div class="client-name">
                            {{ row.web_name|e }}
                        </div>

                        <div class="client-target">
                            {{ row.target|e }}
                        </div>

                        <div class="client-meta">

                            <span
                                class="badge
                                {{ row.status|lower|replace(' ','-') }}"
                            >
                                {{ row.status|e }}
                            </span>

                            <span class="muted">
                                {{ row.name|e }}
                            </span>

                            <span class="muted">
                                #{{ row.id }}
                            </span>

                        </div>

                    </div>


                    <a
                        class="btn dark"
                        href="{{ url_for(
                            'admin_request',
                            request_id=row.id
                        ) }}"
                    >
                        Open Client →
                    </a>

                </div>

                {% endfor %}

            {% else %}

                <div class="empty">

                    No clients yet.

                </div>

            {% endif %}

        </div>

    </div>

</section>
'''

    body = render_template_string(
        body,
        rows=rows,
        pending=pending,
        active=active,
        completed=completed,
        findings_count=findings_count
    )

    import json

    latest_update = max(
        (
            row["updated_at"]
            for row in rows
        ),
        default=""
    )

    script = r'''
async function refreshDashboard(){

    try{

        const response =
            await fetch(
                "__URL__",
                {
                    cache:"no-store"
                }
            );

        if(!response.ok){
            return;
        }

        const data =
            await response.json();

        if(
            data.updated_at !==
            window.currentUpdated
        ){
            location.reload();
        }

    }catch(error){
        console.log(error);
    }
}

window.currentUpdated =
    __UPDATED__;

setInterval(
    refreshDashboard,
    3000
);
'''

    script = (
        script
        .replace(
            "__URL__",
            json.dumps(
                url_for(
                    "api_admin_dashboard"
                )
            )
        )
        .replace(
            "__UPDATED__",
            json.dumps(
                latest_update
            )
        )
    )

    return render_page(
        "Admin Console",
        body,
        script
    )


@app.route(
    "/api/admin/dashboard"
)
@admin_required
def api_admin_dashboard():

    connection = db()

    row = connection.execute(
        """
        SELECT updated_at
        FROM requests
        ORDER BY updated_at DESC
        LIMIT 1
        """
    ).fetchone()

    connection.close()

    return jsonify(
        {
            "updated_at":
                row["updated_at"]
                if row
                else ""
        }
    )


# ============================================================
# SINGLE CLIENT CONTROL CENTER
# ============================================================

@app.route(
    "/admin/request/<int:request_id>",
    methods=["GET", "POST"]
)
@admin_required
def admin_request(
    request_id
):

    item = get_request(
        request_id
    )

    if not item:
        abort(404)

    action_message = ""

    if request.method == "POST":

        action = request.form.get(
            "decision",
            ""
        )

        if (
            action in (
                "ACCEPT",
                "DECLINE"
            )
            and
            item["status"] == "PENDING"
        ):

            new_status = (
                "ACCEPTED"
                if action == "ACCEPT"
                else "DECLINED"
            )

            if action == "ACCEPT":

                system_message = (
                    "Your security request has "
                    "been ACCEPTED. The secure "
                    "chat with the administrator "
                    "is now open."
                )

            else:

                system_message = (
                    "Your security request has "
                    "been DECLINED. The "
                    "administrator has closed "
                    "this request."
                )

            timestamp = now()

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET
                    status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    new_status,
                    timestamp,
                    request_id
                )
            )

            connection.execute(
                """
                INSERT INTO messages(
                    request_id,
                    sender,
                    message,
                    created_at
                )
                VALUES(
                    ?,
                    ?,
                    ?,
                    ?
                )
                """,
                (
                    request_id,
                    "system",
                    system_message,
                    timestamp
                )
            )

            connection.commit()
            connection.close()

            item = get_request(
                request_id
            )

            action_message = (
                "Request updated successfully."
            )

        elif (
            action == "START"
            and
            item["status"] == "ACCEPTED"
        ):

            timestamp = now()

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET
                    status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    "IN PROGRESS",
                    timestamp,
                    request_id
                )
            )

            connection.commit()
            connection.close()

            item = get_request(
                request_id
            )

            action_message = (
                "Assessment moved to IN PROGRESS."
            )

        elif (
            action == "COMPLETE"
            and
            item["status"]
            in (
                "ACCEPTED",
                "IN PROGRESS"
            )
        ):

            timestamp = now()

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET
                    status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    "COMPLETED",
                    timestamp,
                    request_id
                )
            )

            connection.commit()
            connection.close()

            item = get_request(
                request_id
            )

            action_message = (
                "Assessment marked COMPLETED."
            )

        elif (
            action == "REOPEN"
            and
            item["status"] == "DECLINED"
        ):

            timestamp = now()

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET
                    status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    "PENDING",
                    timestamp,
                    request_id
                )
            )

            connection.commit()
            connection.close()

            item = get_request(
                request_id
            )

            action_message = (
                "Request reopened."
            )

    connection = db()

    messages = connection.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id ASC
        """,
        (
            request_id,
        )
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (
            request_id,
        )
    ).fetchall()

    connection.close()

    chat_open = item["status"] in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    )

    body = r'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    CLIENT CONTROL CENTER

                </div>

                <h1 class="title">
                    {{ item.web_name|e }}
                </h1>

                <p class="muted">

                    Request #{{ item.id }}
                    ·
                    {{ item.target|e }}

                </p>

            </div>

            <a
                class="btn dark"
                href="{{ url_for(
                    'admin_dashboard'
                ) }}"
            >
                ← Dashboard
            </a>

        </div>


        {% if action_message %}

        <div class="notice success">

            {{ action_message|e }}

        </div>

        {% endif %}


        <div
            class="kpis"
            style="margin-bottom:18px"
        >

            <div class="kpi panel">

                <strong>
                    #{{ item.id }}
                </strong>

                <span>
                    Request ID
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ item.status }}
                </strong>

                <span>
                    Status
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ "OPEN" if chat_open else "LOCKED" }}
                </strong>

                <span>
                    Chat
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    {{ findings|length }}
                </strong>

                <span>
                    Findings
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
                        Client Information
                    </h3>


                    <p class="muted">

                        <b>
                            Name:
                        </b>

                        {{ item.name|e }}

                    </p>


                    <p class="muted">

                        <b>
                            Email:
                        </b>

                        {{ item.email|e }}

                    </p>


                    <p class="muted">

                        <b>
                            Web Name:
                        </b>

                        {{ item.web_name|e }}

                    </p>


                    <p class="muted">

                        <b>
                            Target:
                        </b>

                        {{ item.target|e }}

                    </p>


                    <p class="muted">

                        <b>
                            Scope:
                        </b>

                        <br>

                        {{ item.scope|e }}

                    </p>

                </div>


                <div
                    class="panel card"
                    style="margin-bottom:18px"
                >

                    <h3>
                        Decision Center
                    </h3>


                    {% if item.status == "PENDING" %}

                    <form
                        method="POST"
                        class="actions"
                    >

                        <button
                            class="btn green"
                            name="decision"
                            value="ACCEPT"
                            type="submit"
                        >
                            ✓ ACCEPT CLIENT
                        </button>

                        <button
                            class="btn red"
                            name="decision"
                            value="DECLINE"
                            type="submit"
                        >
                            ✕ DECLINE CLIENT
                        </button>

                    </form>


                    <p
                        class="muted"
                        style="margin-bottom:0"
                    >

                        Accepting sends an automatic
                        message to the client and
                        unlocks the chat.

                    </p>


                    {% elif item.status == "ACCEPTED" %}

                    <form method="POST">

                        <button
                            class="btn primary"
                            name="decision"
                            value="START"
                            type="submit"
                        >
                            START ASSESSMENT →
                        </button>

                    </form>


                    {% elif item.status == "IN PROGRESS" %}

                    <form method="POST">

                        <button
                            class="btn green"
                            name="decision"
                            value="COMPLETE"
                            type="submit"
                        >
                            MARK COMPLETED ✓
                        </button>

                    </form>


                    {% elif item.status == "DECLINED" %}

                    <form method="POST">

                        <button
                            class="btn yellow"
                            name="decision"
                            value="REOPEN"
                            type="submit"
                        >
                            REOPEN REQUEST
                        </button>

                    </form>


                    {% else %}

                    <span class="badge completed">
                        COMPLETED
                    </span>

                    {% endif %}

                </div>


                <h2 class="title">
                    Findings
                </h2>


                {{ findings_html|safe }}

            </div>


            <div class="panel chat">

                <div class="card">

                    <h3
                        style="margin:0"
                    >
                        Live Client Chat
                    </h3>


                    <p class="muted">

                        {% if chat_open %}

                        Chat is open.

                        {% else %}

                        🔒 Accept the client
                        to unlock chat.

                        {% endif %}

                    </p>

                </div>


                <div class="chatbox">

                    {{ messages_html|safe }}

                </div>


                {% if chat_open %}

                <form
                    class="chatform"
                    method="POST"
                    action="{{ url_for(
                        'admin_message',
                        request_id=item.id
                    ) }}"
                >

                    <input
                        name="message"
                        placeholder="Message client..."
                        required
                    >

                    <button
                        class="btn primary"
                        type="submit"
                    >
                        Send
                    </button>

                </form>

                {% else %}

                <div class="empty">

                    🔒 Accept the client
                    to unlock chat.

                </div>

                {% endif %}

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
                action="{{ url_for(
                    'add_finding',
                    request_id=item.id
                ) }}"
            >

                <div class="grid">

                    <div class="field">

                        <label>
                            Finding Title
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


                    <div
                        class="field full"
                    >

                        <label>
                            Description
                        </label>

                        <textarea
                            name="description"
                            required
                        ></textarea>

                    </div>


                    <div
                        class="field full"
                    >

                        <label>
                            Evidence
                        </label>

                        <textarea
                            name="evidence"
                            required
                        ></textarea>

                    </div>


                    <div
                        class="field full"
                    >

                        <label>
                            Recommendation
                        </label>

                        <textarea
                            name="recommendation"
                            required
                        ></textarea>

                    </div>


                    <div
                        class="field full"
                    >

                        <button
                            class="btn green"
                            type="submit"
                        >
                            PUBLISH FINDING
                        </button>

                    </div>

                </div>

            </form>

        </div>


        <div
            class="actions"
            style="margin-top:18px"
        >

            <a
                class="btn dark"
                href="{{ url_for(
                    'admin_report',
                    request_id=item.id
                ) }}"
            >
                View Full Report →
            </a>

        </div>

    </div>

</section>
'''

    body = render_template_string(
        body,
        item=item,
        action_message=action_message,
        chat_open=chat_open,
        findings=findings,
        findings_html=render_findings(
            findings
        ),
        messages_html=render_messages(
            messages
        )
    )

    import json

    script = r'''
async function refreshClientControl(){

    try{

        const response =
            await fetch(
                "__URL__",
                {
                    cache:"no-store"
                }
            );

        if(!response.ok){
            return;
        }

        const data =
            await response.json();

        if(
            data.updated_at !==
            window.currentUpdated
        ){
            location.reload();
        }

    }catch(error){

        console.log(error);

    }
}

window.currentUpdated =
    __UPDATED__;

setInterval(
    refreshClientControl,
    2500
);
'''

    script = (
        script
        .replace(
            "__URL__",
            json.dumps(
                url_for(
                    "api_admin_request",
                    request_id=request_id
                )
            )
        )
        .replace(
            "__UPDATED__",
            json.dumps(
                item["updated_at"]
            )
        )
    )

    return render_page(
        "Client Control #" + str(request_id),
        body,
        script
    )


@app.route(
    "/api/admin/request/<int:request_id>"
)
@admin_required
def api_admin_request(
    request_id
):

    item = get_request(
        request_id
    )

    if not item:

        return jsonify(
            {
                "error":
                    "not found"
            }
        ), 404

    return jsonify(
        {
            "updated_at":
                item["updated_at"],

            "status":
                item["status"]
        }
    )


@app.route(
    "/admin/request/<int:request_id>/message",
    methods=["POST"]
)
@admin_required
def admin_message(
    request_id
):

    item = get_request(
        request_id
    )

    if not item:

        abort(404)

    if item["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):

        abort(403)

    message = request.form.get(
        "message",
        ""
    ).strip()

    if message:

        timestamp = now()

        connection = db()

        connection.execute(
            """
            INSERT INTO messages(
                request_id,
                sender,
                message,
                created_at
            )
            VALUES(
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                request_id,
                "admin",
                message,
                timestamp
            )
        )

        connection.execute(
            """
            UPDATE requests
            SET updated_at=?
            WHERE id=?
            """,
            (
                timestamp,
                request_id
            )
        )

        connection.commit()
        connection.close()

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id
        )
    )


@app.route(
    "/admin/request/<int:request_id>/finding",
    methods=["POST"]
)
@admin_required
def add_finding(
    request_id
):

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

    allowed = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    if (
        severity not in allowed
        or
        not all(
            [
                title,
                description,
                evidence,
                recommendation
            ]
        )
    ):

        abort(400)

    timestamp = now()

    connection = db()

    connection.execute(
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
        VALUES(
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            request_id,
            title,
            severity,
            description,
            evidence,
            recommendation,
            timestamp
        )
    )

    connection.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            timestamp,
            request_id
        )
    )

    connection.commit()
    connection.close()

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
def admin_report(
    request_id
):

    item = get_request(
        request_id
    )

    if not item:

        abort(404)

    connection = db()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (
            request_id,
        )
    ).fetchall()

    connection.close()

    body = r'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    SECURITY REPORT

                </div>


                <h1 class="title">
                    {{ item.web_name|e }}
                </h1>


                <p class="muted">
                    {{ item.target|e }}
                </p>

            </div>


            <a
                class="btn dark"
                href="{{ url_for(
                    'admin_request',
                    request_id=item.id
                ) }}"
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
                <b>Client:</b>
                {{ item.name|e }}
            </p>


            <p class="muted">
                <b>Email:</b>
                {{ item.email|e }}
            </p>


            <p class="muted">
                <b>Website:</b>
                {{ item.web_name|e }}
            </p>


            <p class="muted">
                <b>Target:</b>
                {{ item.target|e }}
            </p>


            <p class="muted">

                <b>
                    Authorized Scope:
                </b>

                <br>

                {{ item.scope|e }}

            </p>


            <p class="muted">

                <b>
                    Status:
                </b>

                {{ item.status|e }}

            </p>

        </div>


        <h2 class="title">
            Findings
        </h2>


        {{ findings_html|safe }}

    </div>

</section>
'''

    body = render_template_string(
        body,
        item=item,
        findings_html=render_findings(
            findings
        )
    )

    return render_page(
        "Report #" + str(request_id),
        body
    )


# ============================================================
# CLIENT REPORT
# ============================================================

@app.route(
    "/report/<int:request_id>"
)
def client_report(
    request_id
):

    token = request.args.get(
        "token",
        ""
    )

    if not client_authorized(
        request_id,
        token
    ):

        abort(403)

    item = get_request(
        request_id
    )

    connection = db()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (
            request_id,
        )
    ).fetchall()

    connection.close()

    body = r'''
<section class="section">

    <div class="wrap">

        <div class="head">

            <div>

                <div class="status">

                    <span class="dot"></span>

                    PRIVATE SECURITY REPORT

                </div>


                <h1 class="title">
                    {{ item.web_name|e }}
                </h1>


                <p class="muted">
                    {{ item.target|e }}
                </p>

            </div>


            <span
                class="badge
                {{ item.status|lower|replace(' ','-') }}"
            >
                {{ item.status|e }}
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


        {{ findings_html|safe }}


        <div style="margin-top:18px">

            <a
                class="btn dark"
                href="{{ url_for(
                    'client_status',
                    request_id=item.id,
                    token=token
                ) }}"
            >
                ← Back to Portal
            </a>

        </div>

    </div>

</section>
'''

    body = render_template_string(
        body,
        item=item,
        token=token,
        findings_html=render_findings(
            findings
        )
    )

    return render_page(
        "Client Report #" + str(request_id),
        body
    )


# ============================================================
# LOGOUT + ERRORS
# ============================================================

@app.route(
    "/admin/logout"
)
def admin_logout():

    session.clear()

    return redirect(
        url_for(
            "home"
        )
    )


@app.errorhandler(403)
def forbidden(_error):

    return render_page(
        "Access Denied",
        """
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
        """
    ), 403


@app.errorhandler(404)
def not_found(_error):

    return render_page(
        "Not Found",
        """
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

                    <p class="muted">
                        This page does not exist.
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
        """
    ), 404


# ============================================================
# STARTUP
# ============================================================

init_db()


if __name__ == "__main__":

    print(
        "=========================================="
    )

    print(
        "      MATIA // SECURITY CHECK"
    )

    print(
        "=========================================="
    )

    print(
        "Admin email:",
        ADMIN_EMAIL
    )

    print(
        "Port:",
        PORT
    )

    print(
        "Automatic scanning: DISABLED"
    )

    print(
        "Database: READY"
    )

    print(
        "=========================================="
    )

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False
    )
