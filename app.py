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
)


# ============================================================
# MATIA // SECURITY CHECK
# ============================================================

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


# ============================================================
# FLASK
# ============================================================

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

CSS = r"""
:root{
    --bg:#05070b;
    --panel:#0c121b;
    --panel2:#111927;
    --border:#1f2b3d;
    --text:#edf4ff;
    --muted:#8fa1b9;
    --accent:#6d7cff;
    --cyan:#00e5ff;
    --green:#24e99a;
    --red:#ff5069;
    --yellow:#ffc857;
    --orange:#ff9150;
    --shadow:0 24px 80px rgba(0,0,0,.36);
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
        ui-sans-serif,
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
    z-index:100;

    background:rgba(4,6,10,.78);
    backdrop-filter:blur(16px);

    border-bottom:
        1px solid rgba(255,255,255,.06);
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

    margin-top:2px;

    color:var(--muted);

    font-size:9px;
    letter-spacing:1.7px;
}

.links{
    display:flex;
    gap:5px;
}

.links a{
    padding:10px 12px;

    color:var(--muted);

    border-radius:10px;

    transition:.2s;
}

.links a:hover{
    color:var(--text);
    background:rgba(255,255,255,.05);
}

.hero{
    padding:92px 0 48px;
}

.hero-grid,
.two{
    display:grid;

    grid-template-columns:
        1.12fr .88fr;

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

    border-radius:999px;

    background:var(--green);

    box-shadow:
        0 0 16px var(--green);
}

.hero h1{
    margin:
        12px 0 20px;

    font-size:
        clamp(
            46px,
            7vw,
            86px
        );

    line-height:.93;

    letter-spacing:-4px;
}

.grad{
    background:
        linear-gradient(
            90deg,
            #ffffff,
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

    border:
        1px solid var(--border);

    border-radius:22px;

    box-shadow:var(--shadow);
}

.card{
    padding:22px;
}

.code{
    padding:15px;

    border:
        1px solid var(--border);

    border-radius:14px;

    background:#05080d;

    color:#b8c7da;

    font:
        12px/1.9
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;
}

.section{
    padding:36px 0;
}

.title{
    margin:
        0 0 8px;

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
    grid-template-columns:
        repeat(3,1fr);

    margin-top:24px;
}

.kpis{
    grid-template-columns:
        repeat(4,1fr);
}

.cards{
    grid-template-columns:
        repeat(3,1fr);
}

.stat,
.kpi{
    padding:18px;

    border:
        1px solid var(--border);

    border-radius:15px;

    background:
        rgba(255,255,255,.02);
}

.stat strong,
.kpi strong{
    display:block;

    margin-bottom:4px;

    font-size:25px;
}

.stat span,
.kpi span{
    color:var(--muted);
    font-size:12px;
}

.form{
    width:min(900px,100%);
    margin:32px auto 70px;
}

.grid{
    display:grid;

    grid-template-columns:
        1fr 1fr;

    gap:16px;
}

.field{
    display:flex;
    flex-direction:column;
    gap:8px;
}

.full{
    grid-column:1 / -1;
}

label{
    color:#cad6e7;

    font-size:13px;
    font-weight:850;
}

input,
textarea,
select{
    width:100%;

    padding:
        14px 15px;

    border:
        1px solid var(--border);

    border-radius:13px;

    background:#080c12;

    color:var(--text);

    outline:none;

    transition:.2s;
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
    opacity:.85;
    cursor:not-allowed;
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

    padding:
        13px 17px;

    border:0;
    border-radius:12px;

    color:#fff;

    font-weight:900;

    cursor:pointer;

    transition:
        transform .18s,
        box-shadow .18s;
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

    border:
        1px solid var(--border);
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

.notice{
    padding:
        13px 15px;

    margin-bottom:15px;

    border:
        1px solid var(--border);

    border-radius:12px;
}

.error{
    color:#ffbac4;

    background:
        rgba(255,80,105,.09);

    border-color:
        rgba(255,80,105,.23);
}

.success{
    color:#9df9ce;

    background:
        rgba(36,233,154,.08);

    border-color:
        rgba(36,233,154,.22);
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

    border-bottom:
        1px solid var(--border);

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

    padding:
        6px 10px;

    border-radius:999px;

    font-size:11px;
    font-weight:900;

    border:
        1px solid transparent;
}

.pending{
    color:#ffd978;

    background:
        rgba(255,200,87,.08);

    border-color:
        rgba(255,200,87,.2);
}

.accepted,
.completed{
    color:#80f1b8;

    background:
        rgba(36,233,154,.08);

    border-color:
        rgba(36,233,154,.2);
}

.progress{
    color:#79efff;

    background:
        rgba(0,229,255,.08);

    border-color:
        rgba(0,229,255,.2);
}

.declined{
    color:#ff9eac;

    background:
        rgba(255,80,105,.08);

    border-color:
        rgba(255,80,105,.2);
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

    padding:
        11px 13px;

    border:
        1px solid var(--border);

    border-radius:14px;

    background:#0a0f16;
}

.msg.admin{
    align-self:flex-end;

    background:
        rgba(109,124,255,.12);

    border-color:
        rgba(109,124,255,.22);
}

.msg.client{
    align-self:flex-start;
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

    border-top:
        1px solid var(--border);
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
    padding:52px 0;

    color:#66768d;

    font-size:12px;

    text-align:center;
}

.login{
    width:min(480px,92%);
    margin:82px auto;
}

.login .panel{
    padding:28px;
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
        grid-template-columns:
            repeat(2,1fr);
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
        grid-template-columns:
            1fr 1fr;
    }
}
"""


# ============================================================
# HELPERS
# ============================================================

def esc(value):
    return html.escape(
        str(value or ""),
        quote=True
    )


def now():
    return datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def db():
    connection = sqlite3.connect(
        DB_FILE,
        timeout=20
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():
    connection = db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_token TEXT UNIQUE,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            web_name TEXT,
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

    rows = connection.execute(
        """
        SELECT id, client_token, web_name
        FROM requests
        """
    ).fetchall()

    for row in rows:

        token = (
            row["client_token"]
            or secrets.token_urlsafe(32)
        )

        web_name = (
            row["web_name"]
            or "Unnamed Website"
        )

        connection.execute(
            """
            UPDATE requests
            SET client_token=?,
                web_name=?
            WHERE id=?
            """,
            (
                token,
                web_name,
                row["id"]
            )
        )

    connection.commit()
    connection.close()


def get_request(request_id):

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (request_id,)
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


def admin_required(function):

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


def severity_class(value):

    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low"
    }.get(
        (value or "").upper(),
        "info"
    )


def page(
    title,
    body,
    script=""
):

    return f"""
<!doctype html>

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

</html>
"""


def render_messages(rows):

    if not rows:

        return """
        <div class="empty">
            No messages yet.
        </div>
        """

    output = []

    for row in rows:

        role = (
            "admin"
            if row["sender"] == "admin"
            else "client"
        )

        output.append(
            f"""
            <div class="msg {role}">

                <div class="who">
                    {esc(row["sender"])}
                </div>

                <div>
                    {esc(row["message"])}
                </div>

                <div class="time">
                    {esc(row["created_at"])}
                </div>

            </div>
            """
        )

    return "".join(output)


def render_findings(rows):

    if not rows:

        return """
        <div class="panel empty">
            No findings published yet.
        </div>
        """

    output = []

    for row in rows:

        severity = severity_class(
            row["severity"]
        )

        output.append(
            f"""
            <div class="panel finding">

                <div class="sev {severity}">
                    {esc(row["severity"])}
                </div>

                <h3>
                    {esc(row["title"])}
                </h3>

                <p class="muted">

                    <b>
                        Description
                    </b>

                    <br>

                    {esc(row["description"])}

                </p>


                <p class="muted">

                    <b>
                        Evidence
                    </b>

                    <br>

                    {esc(row["evidence"])}

                </p>


                <p class="muted">

                    <b>
                        Recommendation
                    </b>

                    <br>

                    {esc(row["recommendation"])}

                </p>

            </div>
            """
        )

    return "".join(output)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    body = """
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
                Security Operations Portal
            </h2>


            <p class="muted">

                Private client portals,
                admin controls, live polling,
                findings and reports.

            </p>


            <div class="code">

                AUTHORIZATION → REQUIRED
                <br>

                SCOPE → CLIENT DEFINED
                <br>

                SCANNING → MANUAL / AUTHORIZED
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
            From request to final report.
        </p>


        <div class="cards">

            <div class="panel card">

                <h3>
                    01 · Submit
                </h3>

                <p class="muted">

                    Enter name, email,
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

                    Publish findings with
                    severity, evidence and
                    recommendations.

                </p>

            </div>

        </div>

    </div>

</section>
"""

    return page(
        "Home",
        body
    )


# ============================================================
# REQUEST FORM
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

            error = (
                "Name is required."
            )

        elif "@" not in email:

            error = (
                "Valid email is required."
            )

        elif not web_name:

            error = (
                "Web Name is required."
            )

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

            token = secrets.token_urlsafe(
                32
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
                    request.headers.get(
                        "X-Forwarded-For",
                        request.remote_addr or ""
                    )
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

    body = f"""
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

            {
                f'''
                <div class="notice error">
                    {esc(error)}
                </div>
                '''
                if error
                else ""
            }


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
"""

    return page(
        "New Request",
        body
    )


# ============================================================
# CLIENT PORTAL
# ============================================================

@app.route(
    "/status/<int:request_id>"
)
def client_status(request_id):

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
        (request_id,)
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    body = f"""
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
                class="badge
                {item["status"].lower()}"
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
                    PRIVATE
                </strong>

                <span>
                    Client portal
                </span>

            </div>


            <div class="kpi panel">

                <strong>
                    LIVE
                </strong>

                <span>
                    Auto update
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


                <div id="findings">

                    {render_findings(findings)}

                </div>

            </div>


            <div class="panel chat">

                <div class="card">

                    <h3 style="margin:0">
                        Live Analyst Chat
                    </h3>

                    <p class="muted">

                        Updates automatically.

                    </p>

                </div>


                <div
                    class="chatbox"
                    id="client-chat"
                >

                    {render_messages(messages)}

                </div>


                <form
                    class="chatform"
                    method="POST"
                    action="/status/{request_id}/message?token={esc(token)}"
                >

                    <input
                        name="message"
                        placeholder="Type a message..."
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

            </div>

        </div>

    </div>

</section>
"""

    script = f"""
async function checkClientUpdates(){{
    try{{

        const response = await fetch(
            "/api/client/{request_id}?token={esc(token)}",
            {{
                cache:"no-store"
            }}
        );

        if(!response.ok){{
            return;
        }}

        const data = await response.json();

        if(
            data.updated_at !==
            window.currentUpdated
        ){{
            location.reload();
        }}

    }}catch(error){{}}
}}

window.currentUpdated =
    {repr(item["updated_at"])};

setInterval(
    checkClientUpdates,
    2500
);
"""

    return page(
        f"Client Portal #{request_id}",
        body,
        script
    )


@app.route(
    "/api/client/<int:request_id>"
)
def api_client(request_id):

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

    connection = db()

    latest_message = connection.execute(
        """
        SELECT COALESCE(
            MAX(id),
            0
        ) AS value

        FROM messages

        WHERE request_id=?
        """,
        (request_id,)
    ).fetchone()["value"]

    latest_finding = connection.execute(
        """
        SELECT COALESCE(
            MAX(id),
            0
        ) AS value

        FROM findings

        WHERE request_id=?
        """,
        (request_id,)
    ).fetchone()["value"]

    connection.close()

    return jsonify(
        {
            "updated_at":
                item["updated_at"],

            "status":
                item["status"],

            "latest_message":
                latest_message,

            "latest_finding":
                latest_finding
        }
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

    if not client_authorized(
        request_id,
        token
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

    body = f"""
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

            Authorized administrator only.

            Your email is loaded automatically.

        </p>


        {
            f'''
            <div class="notice error">
                {esc(error)}
            </div>
            '''
            if error
            else ""
        }


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
                    value="{esc(ADMIN_EMAIL)}"
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
"""

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

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    finding_count = connection.execute(
        """
        SELECT COUNT(*) AS value
        FROM findings
        """
    ).fetchone()["value"]

    connection.close()

    pending = sum(
        row["status"] == "PENDING"
        for row in rows
    )

    progress = sum(
        row["status"] == "IN PROGRESS"
        for row in rows
    )

    table_rows = []

    for row in rows:

        table_rows.append(
            f"""
            <tr>

                <td>
                    #{row["id"]}
                </td>


                <td>

                    <b>
                        {esc(row["web_name"])}
                    </b>

                    <br>

                    <span class="muted">
                        {esc(row["name"])}
                    </span>

                </td>


                <td>
                    {esc(row["email"])}
                </td>


                <td>
                    {esc(row["target"])}
                </td>


                <td>

                    <span
                        class="badge
                        {row["status"].lower()}"
                    >
                        {esc(row["status"])}
                    </span>

                </td>


                <td>

                    <a
                        class="btn dark"
                        href="/admin/request/{row["id"]}"
                    >
                        Open
                    </a>

                </td>

            </tr>
            """
        )

    script = """
async function refreshAdmin(){

    try{

        const response = await fetch(
            "/api/admin/requests",
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
            data.count !==
            window.currentRequestCount
        ){
            location.reload();
        }

    }catch(error){}
}

window.currentRequestCount =
    __REQUEST_COUNT__;

setInterval(
    refreshAdmin,
    3000
);
""".replace(
        "__REQUEST_COUNT__",
        str(len(rows))
    )

    body = f"""
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

                    Requests, private chats,
                    statuses and findings.

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
                    {len(rows)}
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

                        <th>ID</th>
                        <th>Website</th>
                        <th>Email</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Action</th>

                    </tr>

                </thead>


                <tbody>

                    {
                        "".join(table_rows)
                        or
                        """
                        <tr>

                            <td colspan="6">

                                <div class="empty">
                                    No requests yet.
                                </div>

                            </td>

                        </tr>
                        """
                    }

                </tbody>

            </table>

        </div>

    </div>

</section>
"""

    return page(
        "Admin Console",
        body,
        script
    )


@app.route(
    "/api/admin/requests"
)
@admin_required
def api_admin_requests():

    connection = db()

    count = connection.execute(
        """
        SELECT COUNT(*) AS value
        FROM requests
        """
    ).fetchone()["value"]

    connection.close()

    return jsonify(
        {
            "count": count
        }
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

        allowed = {
            "PENDING",
            "ACCEPTED",
            "IN PROGRESS",
            "COMPLETED",
            "DECLINED"
        }

        if status in allowed:

            timestamp = now()

            connection = db()

            connection.execute(
                """
                UPDATE requests
                SET status=?,
                    updated_at=?
                WHERE id=?
                """,
                (
                    status,
                    timestamp,
                    request_id
                )
            )

            connection.commit()
            connection.close()

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
        (request_id,)
    ).fetchall()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    def selected(value):

        return (
            "selected"
            if item["status"] == value
            else ""
        )

    script = f"""
async function refreshAdminRequest(){

    try{

        const response =
            await fetch(
                "/api/admin/request/{request_id}",
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

    }catch(error){}
}

window.currentUpdated =
    {repr(item["updated_at"])};

setInterval(
    refreshAdminRequest,
    2500
);
"""

    body = f"""
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
                            type="submit"
                            style="margin-top:10px"
                        >
                            UPDATE STATUS
                        </button>

                    </form>

                </div>


                <h2 class="title">
                    Findings
                </h2>


                {render_findings(findings)}

            </div>


            <div class="panel chat">

                <div class="card">

                    <h3 style="margin:0">
                        Client Chat
                    </h3>

                    <p class="muted">

                        Messages update automatically.

                    </p>

                </div>


                <div class="chatbox">

                    {render_messages(messages)}

                </div>


                <form
                    class="chatform"
                    method="POST"
                    action="/admin/request/{request_id}/message"
                >

                    <input
                        name="message"
                        placeholder="Reply to client..."
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
                href="/admin/report/{request_id}"
            >
                View Full Report →
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


@app.route(
    "/api/admin/request/<int:request_id>"
)
@admin_required
def api_admin_request(request_id):

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


# ============================================================
# ADMIN MESSAGE
# ============================================================

@app.route(
    "/admin/request/<int:request_id>/message",
    methods=["POST"]
)
@admin_required
def admin_message(request_id):

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


# ============================================================
# FINDING
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
# REPORTS
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

    connection = db()

    findings = connection.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (request_id,)
    ).fetchall()

    connection.close()

    body = f"""
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
                <b>Client:</b>
                {esc(item["name"])}
            </p>


            <p class="muted">
                <b>Email:</b>
                {esc(item["email"])}
            </p>


            <p class="muted">
                <b>Website:</b>
                {esc(item["web_name"])}
            </p>


            <p class="muted">
                <b>Target:</b>
                {esc(item["target"])}
            </p>


            <p class="muted">

                <b>
                    Authorized Scope:
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


        {render_findings(findings)}

    </div>

</section>
"""

    return page(
        f"Report #{request_id}",
        body
    )


@app.route(
    "/report/<int:request_id>"
)
def client_report(request_id):

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
        (request_id,)
    ).fetchall()

    connection.close()

    body = f"""
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

                This report contains
                findings published by the
                assessment administrator
                and is limited to the
                authorized scope supplied
                with the request.

            </p>

        </div>


        <h2 class="title">
            Security Findings
        </h2>


        {render_findings(findings)}


        <div style="margin-top:18px">

            <a
                class="btn dark"
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
# LOGOUT
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


# ============================================================
# ERROR PAGES
# ============================================================

@app.errorhandler(403)
def forbidden(_error):

    return page(
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

                This private portal link
                is invalid.

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

    return page(
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
        f"Admin email: {ADMIN_EMAIL}"
    )

    print(
        f"Port: {PORT}"
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
