import os, sqlite3, secrets, hmac
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
)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

app.secret_key = os.getenv("MATIA_SECRET_KEY", "CHANGE-ME-IN-RENDER")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "true").lower() == "true",
)

ADMIN_EMAIL = os.getenv(
    "MATIA_ADMIN_EMAIL",
    "kleimatia1@gmail.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv(
    "MATIA_ADMIN_PASSWORD",
    ""
).strip()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "matia_security.db")

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

STATUSES = [
    "PENDING",
    "ACCEPTED",
    "IN PROGRESS",
    "COMPLETED",
    "DECLINED",
]


# ============================================================
# HELPERS
# ============================================================

def now():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=15000")
    return c


def clean(value, limit=4000):
    return str(value or "").strip()[:limit]


def target_ok(value):
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf(value):
    return (
        isinstance(value, str)
        and hmac.compare_digest(
            value,
            session.get("csrf", "")
        )
    )


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(
                url_for(
                    "admin_login",
                    next=request.path
                )
            )

        return fn(*args, **kwargs)

    return wrapper


def notify(
    connection,
    request_id,
    audience,
    kind,
    title,
    body
):
    connection.execute(
        """
        INSERT INTO notifications
        (
            request_id,
            audience,
            kind,
            title,
            body,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            audience,
            kind,
            title,
            body,
            now(),
        ),
    )


def system_message(connection, request_id, text):
    timestamp = now()

    connection.execute(
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
            "SYSTEM",
            text,
            timestamp,
        ),
    )

    connection.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            timestamp,
            request_id,
        ),
    )


def stats(connection):
    return {
        "total": connection.execute(
            "SELECT COUNT(*) FROM requests"
        ).fetchone()[0],

        "waiting": connection.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status='PENDING'
            """
        ).fetchone()[0],

        "active": connection.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status IN ('ACCEPTED', 'IN PROGRESS')
            """
        ).fetchone()[0],

        "findings": connection.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0],
    }


def request_rows(connection):
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM requests
            ORDER BY id DESC
            """
        ).fetchall()
    ]


# ============================================================
# DATABASE
# ============================================================

def init_db():
    connection = db()

    connection.executescript(
        """
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
            client_ip TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT DEFAULT '',
            recommendation TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            audience TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );
        """
    )

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(requests)"
        ).fetchall()
    }

    migrations = [
        ("client_token", "TEXT"),
        ("web_name", "TEXT DEFAULT 'Unnamed Web'"),
        ("client_ip", "TEXT DEFAULT ''"),
    ]

    for name, ddl in migrations:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE requests ADD COLUMN {name} {ddl}"
            )

    missing_tokens = connection.execute(
        """
        SELECT id
        FROM requests
        WHERE client_token IS NULL
           OR client_token=''
        """
    ).fetchall()

    for row in missing_tokens:
        connection.execute(
            """
            UPDATE requests
            SET client_token=?,
                updated_at=?
            WHERE id=?
            """,
            (
                secrets.token_urlsafe(32),
                now(),
                row["id"],
            ),
        )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_msg_req
        ON messages(request_id, id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_find_req
        ON findings(request_id, id)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_notif_aud
        ON notifications(audience, id)
        """
    )

    connection.commit()
    connection.close()


init_db()


# ============================================================
# CSS
# ============================================================

CSS = r"""
:root{
    --bg:#05070d;
    --p:#0b111b;
    --p2:#0f1825;
    --line:#203044;
    --txt:#edf7ff;
    --muted:#8ba0b5;
    --cyan:#00e6ff;
    --green:#42f5a7;
    --red:#ff5e7a;
    --yellow:#ffd166;
    --blue:#62a8ff;
    --purple:#a78bfa;
    --shadow:0 20px 70px rgba(0,0,0,.35);
}

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at 10% 0%,
            #0d2230 0,
            transparent 30%
        ),
        radial-gradient(
            circle at 100% 10%,
            #211438 0,
            transparent 28%
        ),
        var(--bg);
    color:var(--txt);
    font:15px Inter,Segoe UI,Arial,sans-serif;
    min-height:100vh;
}

a{
    color:inherit;
    text-decoration:none;
}

.wrap{
    max-width:1260px;
    margin:auto;
    padding:24px 18px 70px;
}

.nav{
    position:sticky;
    top:0;
    z-index:50;
    background:#05070dd9;
    backdrop-filter:blur(15px);
    border-bottom:1px solid #152334;
}

.navin{
    max-width:1260px;
    margin:auto;
    padding:14px 18px;
    display:flex;
    justify-content:space-between;
    gap:15px;
    align-items:center;
}

.brand{
    font-weight:950;
    letter-spacing:.08em;
}

.brand span{
    color:var(--cyan);
}

.links{
    display:flex;
    gap:7px;
    flex-wrap:wrap;
}

.links a{
    padding:9px 11px;
    border-radius:10px;
    color:var(--muted);
}

.links a:hover{
    background:#101a28;
    color:var(--txt);
}

.hero{
    padding:65px 0 35px;
}

.eyebrow,
.kicker{
    color:var(--cyan);
    font-size:11px;
    font-weight:900;
    letter-spacing:.17em;
    text-transform:uppercase;
}

.hero h1{
    font-size:clamp(42px,7vw,88px);
    line-height:.95;
    margin:10px 0 16px;
}

.hero p{
    color:var(--muted);
    max-width:820px;
    line-height:1.75;
    font-size:18px;
}

.grid{
    display:grid;
    gap:16px;
}

.g4{
    grid-template-columns:repeat(4,1fr);
}

.g3{
    grid-template-columns:repeat(3,1fr);
}

.g2{
    grid-template-columns:repeat(2,1fr);
}

@media(max-width:900px){
    .g4,
    .g3,
    .g2{
        grid-template-columns:1fr;
    }

    .navin{
        align-items:flex-start;
        flex-direction:column;
    }

    .hero{
        padding-top:35px;
    }
}

.card{
    background:
        linear-gradient(
            180deg,
            #0d1622ee,
            #080d15ee
        );
    border:1px solid var(--line);
    border-radius:18px;
    padding:18px;
    box-shadow:var(--shadow);
}

.muted{
    color:var(--muted);
}

.stat .n{
    font-size:32px;
    font-weight:950;
}

.stat .l{
    font-size:11px;
    color:var(--muted);
    letter-spacing:.12em;
    text-transform:uppercase;
}

.spaced{
    display:flex;
    justify-content:space-between;
    gap:12px;
    align-items:center;
    flex-wrap:wrap;
}

.btn{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:8px;
    border:1px solid var(--line);
    background:#101827;
    color:var(--txt);
    padding:10px 14px;
    border-radius:11px;
    font-weight:850;
    cursor:pointer;
}

.btn:hover{
    border-color:#42617f;
    transform:translateY(-1px);
}

.btn.primary{
    background:
        linear-gradient(
            135deg,
            #00b3d3,
            #28e6a7
        );
    color:#021116;
    border:none;
}

.btn.green{
    color:var(--green);
    background:#0c2019;
    border-color:#214e3c;
}

.btn.red{
    color:#ff8ca0;
    background:#241017;
    border-color:#5a2634;
}

.btn.blue{
    color:#91c5ff;
    background:#0e1d31;
    border-color:#28496d;
}

.btn.yellow{
    color:var(--yellow);
    background:#251e0d;
    border-color:#5b4d22;
}

.btn.small{
    padding:7px 10px;
    font-size:12px;
}

.btnrow{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
}

input,
textarea,
select{
    width:100%;
    background:#070c14;
    border:1px solid var(--line);
    color:var(--txt);
    border-radius:11px;
    padding:11px 12px;
    outline:none;
}

input:focus,
textarea:focus,
select:focus{
    border-color:#287f94;
    box-shadow:0 0 0 3px #00e6ff10;
}

.field{
    margin-bottom:13px;
}

.field label{
    display:block;
    color:#aabdce;
    font-size:11px;
    font-weight:850;
    letter-spacing:.08em;
    text-transform:uppercase;
    margin-bottom:6px;
}

textarea{
    min-height:115px;
    resize:vertical;
}

.badge{
    display:inline-flex;
    padding:6px 9px;
    border-radius:999px;
    border:1px solid var(--line);
    font-size:10px;
    font-weight:950;
    letter-spacing:.06em;
}

.PENDING{
    color:var(--yellow);
}

.ACCEPTED{
    color:var(--green);
}

.INPROGRESS{
    color:var(--blue);
}

.COMPLETED{
    color:#c2d2ff;
}

.DECLINED{
    color:var(--red);
}

.tablewrap{
    overflow:auto;
    border:1px solid var(--line);
    border-radius:14px;
}

.table{
    width:100%;
    border-collapse:collapse;
    min-width:900px;
}

.table th,
.table td{
    padding:12px 13px;
    border-bottom:1px solid #172334;
    text-align:left;
}

.table th{
    font-size:10px;
    color:#8297ab;
    text-transform:uppercase;
    letter-spacing:.09em;
    background:#0a111b;
}

.table tr:hover td{
    background:#0c1520;
}

.terminal{
    background:#030508;
    border:1px solid #172638;
    border-radius:16px;
    min-height:360px;
    display:flex;
    flex-direction:column;
}

.termhead{
    padding:10px 13px;
    border-bottom:1px solid #152333;
    color:#7e94a8;
    display:flex;
    justify-content:space-between;
    font:12px monospace;
}

.termbody{
    padding:14px;
    flex:1;
    overflow:auto;
    font:13px/1.65 ui-monospace,monospace;
}

.cmdline{
    display:flex;
    gap:8px;
    border-top:1px solid #152333;
    padding:11px;
}

.cmdline input{
    font:13px monospace;
}

.green{
    color:var(--green);
}

.chat{
    height:420px;
    display:flex;
    flex-direction:column;
}

.msgs{
    flex:1;
    overflow:auto;
    display:flex;
    flex-direction:column;
    gap:9px;
    padding:8px;
}

.msg{
    max-width:82%;
    padding:10px 12px;
    border-radius:14px;
    background:#0c1724;
    border:1px solid #1b2a3d;
}

.msg.me{
    margin-left:auto;
    background:#09231d;
    border-color:#1b4b3c;
}

.meta{
    font-size:10px;
    color:#7890a5;
    margin-bottom:5px;
}

.chatinput{
    display:flex;
    gap:8px;
    padding-top:9px;
}

.chatinput input{
    flex:1;
}

.notice{
    padding:11px;
    border:1px solid var(--line);
    border-radius:12px;
    background:#0a121d;
}

.live{
    display:inline-flex;
    align-items:center;
    gap:6px;
    color:var(--green);
    font-weight:900;
    font-size:11px;
}

.live:before{
    content:'';
    width:8px;
    height:8px;
    border-radius:50%;
    background:var(--green);
    box-shadow:0 0 16px var(--green);
    animation:pulse 1.6s infinite;
}

@keyframes pulse{
    50%{
        opacity:.35;
        transform:scale(.7);
    }
}

.timeline{
    display:flex;
    gap:8px;
    align-items:stretch;
    overflow:auto;
}

.step{
    min-width:145px;
    padding:12px;
    border:1px solid var(--line);
    border-radius:12px;
    background:#0a111b;
}

.step.on{
    border-color:#2e8d71;
    background:#092119;
}

.step .num{
    font-weight:950;
    color:var(--cyan);
}

.sep{
    height:1px;
    background:#1a2737;
    margin:15px 0;
}

.empty{
    padding:25px;
    text-align:center;
    color:var(--muted);
}

.sev{
    font-size:10px;
    font-weight:950;
    padding:5px 8px;
    border-radius:999px;
    border:1px solid var(--line);
}

.sev-CRITICAL,
.sev-HIGH{
    color:#ff8b9e;
}

.sev-MEDIUM{
    color:var(--yellow);
}

.sev-LOW{
    color:var(--green);
}

.sev-INFO{
    color:var(--blue);
}

.mono{
    font-family:ui-monospace,Consolas,monospace;
}

.center{
    text-align:center;
}
"""


# ============================================================
# PAGE SHELL
# ============================================================

def page(title, body, **ctx):
    shell = r"""
<!doctype html>

<html>
<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    {{ title }} · MATIA // SECURITY CHECK
</title>

<style>
{{ css|safe }}
</style>

</head>

<body>

<div class="nav">

    <div class="navin">

        <a
            class="brand"
            href="{{ url_for('home') }}"
        >
            MATIA
            <span>//</span>
            SECURITY CHECK
        </a>

        <div class="links">

            <a href="{{ url_for('home') }}">
                Home
            </a>

            <a href="{{ url_for('how_it_works') }}">
                How It Works
            </a>

            <a href="{{ url_for('new_request') }}">
                Request Audit
            </a>

            {% if session.get('admin') %}

            <a href="{{ url_for('admin_dashboard') }}">
                Admin SOC
            </a>

            <a href="{{ url_for('admin_logout') }}">
                Logout
            </a>

            {% else %}

            <a href="{{ url_for('admin_login') }}">
                Admin
            </a>

            {% endif %}

        </div>

    </div>

</div>

<main class="wrap">

    {{ inner|safe }}

</main>

<script>

function esc(s){

    return String(s ?? '').replace(
        /[&<>\"']/g,
        m => ({
            '&':'&amp;',
            '<':'&lt;',
            '>':'&gt;',
            '"':'&quot;',
            "'":'&#39;'
        }[m])
    );

}


function toast(text){

    let box = document.createElement("div");

    box.textContent = text;

    box.style =
        "position:fixed;" +
        "right:18px;" +
        "bottom:18px;" +
        "z-index:99;" +
        "padding:12px 14px;" +
        "border:1px solid #2a4259;" +
        "border-radius:12px;" +
        "background:#09111b;" +
        "color:#eaf7ff;" +
        "box-shadow:0 15px 40px #0008";

    document.body.appendChild(box);

    setTimeout(
        () => box.remove(),
        3200
    );

}


async function notifyMe(title, body){

    if (!("Notification" in window)){
        return;
    }

    if (Notification.permission === "default"){

        try{
            await Notification.requestPermission();
        }
        catch(e){}

    }

    if (Notification.permission === "granted"){

        new Notification(
            title,
            {
                body: body
            }
        );

    }

}


async function sendJSON(url, options = {}){

    let response = await fetch(
        url,
        {
            headers:{
                "Content-Type":"application/json",
                ...(options.headers || {})
            },
            ...options
        }
    );

    let data = await response
        .json()
        .catch(() => ({}));

    if (!response.ok){

        throw new Error(
            data.error || "Request failed"
        );

    }

    return data;
}

</script>

</body>
</html>
"""

    rendered_body = render_template_string(
        body,
        **ctx
    )

    return render_template_string(
        shell,
        title=title,
        css=CSS,
        inner=rendered_body,
        **ctx
    )


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
    ] = "same-origin"

    return response


@app.context_processor
def inject_helpers():

    return {
        "csrf_token": csrf_token
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    body = r"""

<section class="hero">

    <div class="eyebrow">
        AUTHORIZATION-FIRST SECURITY OPERATIONS
    </div>

    <h1>
        Inspect.
        Document.
        <br>

        <span style="color:var(--cyan)">
            Communicate.
        </span>
    </h1>

    <p>
        MATIA // SECURITY CHECK is a request-to-report
        portal for authorized web security assessments,
        with an Admin SOC, real client↔admin chat,
        evidence-ready findings and live status updates.
    </p>

    <div class="btnrow">

        <a
            class="btn primary"
            href="{{ url_for('new_request') }}"
        >
            ＋ Submit Security Request
        </a>

        <a
            class="btn"
            href="{{ url_for('how_it_works') }}"
        >
            ⌁ How It Works
        </a>

    </div>

</section>


<div class="grid g4">

    <div class="card">

        <div class="kicker">
            01
        </div>

        <h3>
            Request
        </h3>

        <p class="muted">
            Client submits target,
            scope and explicit authorization.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            02
        </div>

        <h3>
            Review
        </h3>

        <p class="muted">
            Admin receives the request
            in a live SOC queue.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            03
        </div>

        <h3>
            Collaborate
        </h3>

        <p class="muted">
            Accepted clients unlock
            real two-way chat.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            04
        </div>

        <h3>
            Report
        </h3>

        <p class="muted">
            Published findings become
            part of the client report.
        </p>

    </div>

</div>

"""

    return page(
        "Home",
        body
    )


# ============================================================
# HOW IT WORKS
# ============================================================

@app.route("/how-it-works")
def how_it_works():

    body = r"""

<div
    class="spaced"
    style="margin:25px 0"
>

    <div>

        <div class="eyebrow">
            HOW THE APP WORKS
        </div>

        <h1 style="margin:7px 0">
            From request →
            live assessment →
            report.
        </h1>

    </div>

    <span class="live">
        SYSTEM ONLINE
    </span>

</div>


<div class="grid g2">


    <div class="card">

        <div class="kicker">
            01 · Submit
        </div>

        <h2>
            Client creates a security request
        </h2>

        <p class="muted">
            The client enters name, email,
            website name, target URL and the
            authorized testing scope.
            A private token is generated
            for the portal.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            02 · Queue
        </div>

        <h2>
            Admin sees the request
        </h2>

        <p class="muted">
            Every request appears in the
            Admin SOC queue.
            The dashboard tracks total,
            waiting, active and finding counts.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            03 · Decision
        </div>

        <h2>
            Accept or decline
        </h2>

        <p class="muted">
            Accepting unlocks the client chat.
            Declining closes the request.
            A declined request can be reopened
            by the administrator.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            04 · Live chat
        </div>

        <h2>
            Real two-way communication
        </h2>

        <p class="muted">
            Messages are stored server-side.
            Both sides poll the database for
            new messages, so the chat updates
            without manually refreshing the page.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            05 · Assessment
        </div>

        <h2>
            Track the assessment lifecycle
        </h2>

        <p class="muted">
            Admin can move the request from
            ACCEPTED → IN PROGRESS →
            COMPLETED and the client sees
            the status change.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            06 · Findings
        </div>

        <h2>
            Publish structured findings
        </h2>

        <p class="muted">
            Each finding can contain severity,
            description, evidence and recommendation.
            Published findings appear in the client report.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            07 · Notifications
        </div>

        <h2>
            Real browser notifications
        </h2>

        <p class="muted">
            When notification permission is granted,
            the app can show actual browser/OS
            notifications for relevant new activity
            while the portal is open.
        </p>

    </div>


    <div class="card">

        <div class="kicker">
            08 · Security
        </div>

        <h2>
            Authorization stays central
        </h2>

        <p class="muted">
            The portal is designed for authorized
            assessments. It does not automatically
            scan or exploit targets; it is a workflow
            and reporting system.
        </p>

    </div>

</div>


<div
    class="card"
    style="margin-top:18px"
>

    <div class="kicker">
        STATUS MAP
    </div>

    <div
        class="timeline"
        style="margin-top:12px"
    >

        <div class="step on">

            <div class="num">
                01
            </div>

            <b>
                PENDING
            </b>

            <div class="muted">
                Waiting for review
            </div>

        </div>


        <div class="step">

            <div class="num">
                02
            </div>

            <b>
                ACCEPTED
            </b>

            <div class="muted">
                Chat unlocked
            </div>

        </div>


        <div class="step">

            <div class="num">
                03
            </div>

            <b>
                IN PROGRESS
            </b>

            <div class="muted">
                Assessment active
            </div>

        </div>


        <div class="step">

            <div class="num">
                04
            </div>

            <b>
                COMPLETED
            </b>

            <div class="muted">
                Report ready
            </div>

        </div>

    </div>

</div>

"""

    return page(
        "How It Works",
        body
    )


# ============================================================
# CLIENT REQUEST
# ============================================================

@app.route(
    "/request",
    methods=["GET", "POST"]
)
def new_request():

    if request.method == "POST":

        name = clean(
            request.form.get("name"),
            120
        )

        email = clean(
            request.form.get("email"),
            180
        ).lower()

        web_name = clean(
            request.form.get("web_name"),
            160
        )

        target = clean(
            request.form.get("target"),
            500
        )

        scope = clean(
            request.form.get("scope"),
            6000
        )

        authorized = request.form.get(
            "authorized"
        )

        if (
            not all(
                [
                    name,
                    email,
                    web_name,
                    target,
                    scope,
                ]
            )
            or "@" not in email
            or not target_ok(target)
            or not authorized
        ):

            return page(
                "Request",
                r"""
                <div
                    class="card"
                    style="max-width:760px;margin:35px auto"
                >

                    <div class="eyebrow">
                        INVALID REQUEST
                    </div>

                    <h2>
                        Check the form
                    </h2>

                    <p class="muted">
                        Use a valid HTTP/HTTPS target,
                        valid email, complete scope
                        and confirm you have authorization.
                    </p>

                    <a
                        class="btn"
                        href="{{ url_for('new_request') }}"
                    >
                        Go Back
                    </a>

                </div>
                """
            )

        timestamp = now()

        token = secrets.token_urlsafe(32)

        client_ip = (
            request.headers.get(
                "X-Forwarded-For"
            )
            or request.remote_addr
            or ""
        )[:120]

        connection = db()

        cursor = connection.execute(
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
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
                client_ip,
            ),
        )

        request_id = cursor.lastrowid

        system_message(
            connection,
            request_id,
            "Your security request has been received and is now PENDING review."
        )

        notify(
            connection,
            request_id,
            "ADMIN",
            "REQUEST",
            "New security request",
            f"Client #{request_id} · {web_name} · {name}",
        )

        connection.commit()
        connection.close()

        return redirect(
            url_for(
                "client_status",
                rid=request_id,
                token=token,
            )
        )

    body = r"""

<div
    class="card"
    style="max-width:820px;margin:30px auto"
>

    <div class="eyebrow">
        REQUEST ACCESS
    </div>

    <h1 style="margin:7px 0 20px">
        Start an authorized assessment
    </h1>

    <form method="post">

        <div class="grid g2">

            <div class="field">

                <label>
                    Your Name
                </label>

                <input
                    name="name"
                    required
                    maxlength="120"
                >

            </div>


            <div class="field">

                <label>
                    Your Email
                </label>

                <input
                    name="email"
                    type="email"
                    required
                    maxlength="180"
                >

            </div>


            <div class="field">

                <label>
                    Web Name
                </label>

                <input
                    name="web_name"
                    required
                    maxlength="160"
                    placeholder="My Website"
                >

            </div>


            <div class="field">

                <label>
                    Web Target
                </label>

                <input
                    name="target"
                    type="url"
                    required
                    placeholder="https://example.com"
                >

            </div>

        </div>


        <div class="field">

            <label>
                Authorized Scope
            </label>

            <textarea
                name="scope"
                required
                maxlength="6000"
                placeholder="Example: public website only; no account takeover; no destructive actions."
            ></textarea>

        </div>


        <label
            style="
                display:flex;
                gap:10px;
                align-items:flex-start;
                color:#a9b9ca
            "
        >

            <input
                type="checkbox"
                name="authorized"
                style="width:auto;margin-top:4px"
                required
            >

            <span>
                I confirm that I own the target
                or have explicit permission to request
                testing within the scope above.
            </span>

        </label>


        <div
            class="btnrow"
            style="margin-top:18px"
        >

            <button
                class="btn primary"
            >
                Create Security Request
            </button>

            <a
                class="btn"
                href="{{ url_for('how_it_works') }}"
            >
                How It Works
            </a>

        </div>

    </form>

</div>

"""

    return page(
        "Request Security Assessment",
        body
    )


# ============================================================
# CLIENT STATUS
# ============================================================

@app.route("/status/<int:rid>")
def client_status(rid):

    token = request.args.get(
        "token",
        ""
    )

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if (
        not client
        or not hmac.compare_digest(
            client["client_token"] or "",
            token,
        )
    ):

        connection.close()
        abort(404)

    # AJAX mode for live polling
    if request.args.get("ajax") == "1":

        since = int(
            request.args.get(
                "since",
                "0"
            ) or 0
        )

        messages = [
            dict(row)
            for row in connection.execute(
                """
                SELECT *
                FROM messages
                WHERE request_id=?
                  AND id>?
                ORDER BY id
                """,
                (rid, since),
            ).fetchall()
        ]

        data = {
            "ok": True,
            "status": client["status"],
            "updated_at": client["updated_at"],
            "messages": messages,
        }

        connection.close()

        return jsonify(data)

    messages = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
            ORDER BY id
            """,
            (rid,),
        ).fetchall()
    ]

    findings = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (rid,),
        ).fetchall()
    ]

    connection.close()

    body = r"""

<div
    class="spaced"
    style="margin:25px 0"
>

    <div>

        <div class="eyebrow">
            CLIENT PORTAL · #{{ client['id'] }}
        </div>

        <h1 style="margin:7px 0">
            {{ client['web_name'] }}
        </h1>

        <div class="muted">
            {{ client['target'] }}
        </div>

    </div>

    <span
        id="statusBadge"
        class="badge {{ client['status'].replace(' ','') }}"
    >
        {{ client['status'] }}
    </span>

</div>


<div class="card">

    <div class="spaced">

        <div>

            <div class="kicker">
                Assessment lifecycle
            </div>

            <h2
                id="statusHeading"
                style="margin:5px 0"
            >
                {{ client['status'] }}
            </h2>

        </div>

        <span class="live">
            LIVE SYNC
        </span>

    </div>


    <div
        class="timeline"
        style="margin-top:14px"
    >

        <div
            class="step
            {% if client['status'] in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}
            on
            {% endif %}"
        >

            <div class="num">
                01
            </div>

            <b>
                ACCEPTED
            </b>

            <div class="muted">
                Chat unlock
            </div>

        </div>


        <div
            class="step
            {% if client['status'] in ['IN PROGRESS','COMPLETED'] %}
            on
            {% endif %}"
        >

            <div class="num">
                02
            </div>

            <b>
                IN PROGRESS
            </b>

            <div class="muted">
                Assessment
            </div>

        </div>


        <div
            class="step
            {% if client['status']=='COMPLETED' %}
            on
            {% endif %}"
        >

            <div class="num">
                03
            </div>

            <b>
                COMPLETED
            </b>

            <div class="muted">
                Report ready
            </div>

        </div>

    </div>

</div>


<div
    class="grid g2"
    style="margin-top:16px"
>

    <div class="card">

        <div class="spaced">

            <h2>
                💬 Live Chat
            </h2>

            <span
                id="chatState"
                class="muted"
            >
                {% if client['status']
                    in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}
                    UNLOCKED
                {% else %}
                    LOCKED
                {% endif %}
            </span>

        </div>


        <div class="chat">

            <div
                class="msgs"
                id="msgs"
            >

                {% for message in messages %}

                <div
                    class="msg
                    {% if message['sender']=='CLIENT' %}
                    me
                    {% endif %}"
                >

                    <div class="meta">

                        {{ message['sender'] }}
                        ·
                        {{ message['created_at'] }}

                    </div>

                    <div
                        style="white-space:pre-wrap"
                    >
                        {{ message['message'] }}
                    </div>

                </div>

                {% endfor %}

            </div>


            {% if client['status']
                in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

            <div class="chatinput">

                <input
                    id="msgInput"
                    placeholder="Write to administrator..."
                    maxlength="4000"
                >

                <button
                    class="btn primary"
                    onclick="sendMsg()"
                >
                    Send
                </button>

            </div>

            {% else %}

            <div class="muted">
                Chat opens after admin approval.
            </div>

            {% endif %}

        </div>

    </div>


    <div class="card">

        <div class="spaced">

            <h2>
                🔎 Findings
            </h2>

            <a
                class="btn small"
                href="{{
                    url_for(
                        'client_report',
                        rid=client['id'],
                        token=client['client_token']
                    )
                }}"
            >
                Full Report
            </a>

        </div>


        {% for finding in findings %}

        <div
            class="card"
            style="
                margin-top:10px;
                padding:13px;
                box-shadow:none
            "
        >

            <div class="spaced">

                <b>
                    {{ finding['title'] }}
                </b>

                <span
                    class="sev sev-{{ finding['severity'] }}"
                >
                    {{ finding['severity'] }}
                </span>

            </div>

            <p
                class="muted"
                style="white-space:pre-wrap"
            >
                {{ finding['description'] }}
            </p>

        </div>

        {% else %}

        <div class="empty">
            No findings published yet.
        </div>

        {% endfor %}

    </div>

</div>


<script>

const RID = {{ client['id'] }};
const TOKEN = {{ client['client_token']|tojson }};

let lastMsg =
    {{ (messages[-1]['id'] if messages else 0) }};

let baseline =
    {{ client['updated_at']|tojson }};

let primed = false;


function addMsg(message){

    let element =
        document.createElement("div");

    element.className =
        "msg " +
        (
            message.sender === "CLIENT"
            ? "me"
            : ""
        );

    element.innerHTML =
        '<div class="meta">' +
        esc(message.sender) +
        ' · ' +
        esc(message.created_at) +
        '</div>' +
        '<div style="white-space:pre-wrap">' +
        esc(message.message) +
        '</div>';

    let box =
        document.getElementById("msgs");

    box.appendChild(element);

    box.scrollTop =
        box.scrollHeight;
}


async function pollClient(){

    try{

        let data =
            await fetch(
                `/status/${RID}?token=` +
                encodeURIComponent(TOKEN) +
                `&ajax=1&since=${lastMsg}`
            ).then(
                response => response.json()
            );

        if (!data.ok){
            return;
        }

        for (
            const message
            of data.messages || []
        ){

            lastMsg =
                Math.max(
                    lastMsg,
                    message.id
                );

            if (
                message.sender !== "CLIENT"
                || primed
            ){

                addMsg(message);

                if (
                    message.sender !== "CLIENT"
                ){

                    await notifyMe(
                        "MATIA // SECURITY CHECK",
                        message.message
                    );

                }

            }

        }

        if (
            data.updated_at !== baseline
        ){

            baseline =
                data.updated_at;

            if (primed){
                location.reload();
            }

        }

        primed = true;

    }catch(error){}

}


async function sendMsg(){

    let input =
        document.getElementById("msgInput");

    let message =
        input.value.trim();

    if (!message){
        return;
    }

    try{

        await sendJSON(
            `/status/${RID}/message`,
            {
                method:"POST",
                body:JSON.stringify({
                    token:TOKEN,
                    message:message
                })
            }
        );

        input.value = "";

        await pollClient();

    }catch(error){

        toast(error.message);

    }

}


pollClient();

setInterval(
    pollClient,
    2200
);

</script>

"""

    return page(
        f"Client #{rid}",
        body,
        client=client,
        messages=messages,
        findings=findings,
    )


# ============================================================
# CLIENT MESSAGE
# ============================================================

@app.route(
    "/status/<int:rid>/message",
    methods=["POST"]
)
def client_message(rid):

    data = request.get_json(
        silent=True
    ) or {}

    token = clean(
        data.get("token"),
        300
    )

    message = clean(
        data.get("message"),
        4000
    )

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if (
        not client
        or not hmac.compare_digest(
            client["client_token"] or "",
            token,
        )
    ):

        connection.close()

        return jsonify(
            ok=False,
            error="Invalid client token"
        ), 403

    if client["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED",
    ):

        connection.close()

        return jsonify(
            ok=False,
            error="Chat is locked until the request is accepted"
        ), 403

    if not message:

        connection.close()

        return jsonify(
            ok=False,
            error="Message is empty"
        ), 400

    timestamp = now()

    connection.execute(
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
            rid,
            "CLIENT",
            message,
            timestamp,
        ),
    )

    connection.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            timestamp,
            rid,
        ),
    )

    notify(
        connection,
        rid,
        "ADMIN",
        "MESSAGE",
        f"Client #{rid} sent a message",
        message,
    )

    connection.commit()
    connection.close()

    return jsonify(ok=True)


# ============================================================
# CLIENT REPORT
# ============================================================

@app.route("/report/<int:rid>")
def client_report(rid):

    token = request.args.get(
        "token",
        ""
    )

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if (
        not client
        or not hmac.compare_digest(
            client["client_token"] or "",
            token,
        )
    ):

        connection.close()
        abort(404)

    findings = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (rid,),
        ).fetchall()
    ]

    connection.close()

    counts = {
        severity:
            sum(
                finding["severity"] == severity
                for finding in findings
            )
        for severity in SEVERITIES
    }

    body = r"""

<div
    class="spaced"
    style="margin:25px 0"
>

    <div>

        <div class="eyebrow">
            CLIENT SECURITY REPORT
        </div>

        <h1 style="margin:7px 0">
            {{ client['web_name'] }}
        </h1>

        <div class="muted">
            {{ client['target'] }}
        </div>

    </div>

    <span
        class="badge {{ client['status'].replace(' ','') }}"
    >
        {{ client['status'] }}
    </span>

</div>


<div class="grid g4">

    {% for severity in severities %}

    <div class="card stat">

        <div class="l">
            {{ severity }}
        </div>

        <div class="n">
            {{ counts[severity] }}
        </div>

    </div>

    {% endfor %}

</div>


<div
    class="card"
    style="margin-top:16px"
>

    <div class="kicker">
        AUTHORIZED SCOPE
    </div>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{ client['scope'] }}
    </p>

</div>


{% for finding in findings %}

<div
    class="card"
    style="margin-top:12px"
>

    <div class="spaced">

        <h2 style="margin:0">
            {{ finding['title'] }}
        </h2>

        <span
            class="sev sev-{{ finding['severity'] }}"
        >
            {{ finding['severity'] }}
        </span>

    </div>


    <div class="sep"></div>


    <div class="kicker">
        Description
    </div>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{ finding['description'] }}
    </p>


    <div class="kicker">
        Evidence
    </div>

    <div
        class="mono"
        style="
            white-space:pre-wrap;
            background:#04070b;
            border:1px solid #142131;
            padding:13px;
            border-radius:12px;
            margin:7px 0 14px
        "
    >
        {{
            finding['evidence']
            or
            'No evidence supplied.'
        }}
    </div>


    <div class="kicker">
        Recommendation
    </div>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{
            finding['recommendation']
            or
            'No recommendation supplied.'
        }}
    </p>

</div>

{% else %}

<div
    class="card empty"
    style="margin-top:16px"
>
    No findings published yet.
</div>

{% endfor %}

"""

    return page(
        f"Report #{rid}",
        body,
        client=client,
        findings=findings,
        counts=counts,
        severities=SEVERITIES,
    )


# ============================================================
# CLIENT NOTIFICATIONS
# ============================================================

@app.route(
    "/api/client/<int:rid>/notifications"
)
def client_notifications(rid):

    token = clean(
        request.args.get("token"),
        300
    )

    since = int(
        request.args.get(
            "since",
            "0"
        ) or 0
    )

    connection = db()

    client = connection.execute(
        """
        SELECT client_token
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if (
        not client
        or not hmac.compare_digest(
            client["client_token"] or "",
            token,
        )
    ):

        connection.close()

        return jsonify(
            ok=False
        ), 403

    notifications = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM notifications
            WHERE request_id=?
              AND audience='CLIENT'
              AND id>?
            ORDER BY id
            """,
            (
                rid,
                since,
            ),
        ).fetchall()
    ]

    connection.close()

    return jsonify(
        ok=True,
        notifications=notifications
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if session.get("admin"):
        return redirect(
            url_for("admin_dashboard")
        )

    error = ""

    if request.method == "POST":

        email = clean(
            request.form.get("email"),
            180
        ).lower()

        password = str(
            request.form.get("password") or ""
        )

        if (
            email == ADMIN_EMAIL
            and ADMIN_PASSWORD
            and hmac.compare_digest(
                password,
                ADMIN_PASSWORD
            )
        ):

            session.clear()

            session["admin"] = True

            session["csrf"] = (
                secrets.token_urlsafe(24)
            )

            return redirect(
                request.args.get("next")
                or
                url_for("admin_dashboard")
            )

        error = "Invalid admin credentials."

    body = r"""

<div
    class="card"
    style="
        max-width:460px;
        margin:70px auto
    "
>

    <div class="eyebrow">
        AUTHORIZED ADMIN
    </div>

    <h1>
        Admin SOC Login
    </h1>

    <form method="post">

        <div class="field">

            <label>
                Email
            </label>

            <input
                name="email"
                type="email"
                autocomplete="username"
                required
                value="{{ admin_email }}"
            >

        </div>


        <div class="field">

            <label>
                Password
            </label>

            <input
                name="password"
                type="password"
                autocomplete="current-password"
                required
            >

        </div>


        <button
            class="btn primary"
            style="width:100%"
        >
            Enter Security Operations
        </button>

    </form>


    {% if error %}

    <p
        style="color:var(--red);margin-top:12px"
    >
        {{ error }}
    </p>

    {% endif %}

</div>

"""

    return page(
        "Admin Login",
        body,
        error=error,
        admin_email=ADMIN_EMAIL,
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    connection = db()

    rows = request_rows(
        connection
    )

    stat_data = stats(
        connection
    )

    feed = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM notifications
            WHERE audience='ADMIN'
            ORDER BY id DESC
            LIMIT 12
            """
        ).fetchall()
    ]

    latest_updated = connection.execute(
        """
        SELECT COALESCE(MAX(updated_at),'')
        FROM requests
        """
    ).fetchone()[0]

    connection.close()

    body = r"""

<div
    class="spaced"
    style="margin:24px 0 15px"
>

    <div>

        <div class="eyebrow">
            SECURITY OPERATIONS CENTER
        </div>

        <h1 style="margin:7px 0">
            Admin Command Deck
        </h1>

        <div class="muted">
            One client at a time · live queue ·
            evidence-ready reporting
        </div>

    </div>

    <span class="live">
        REAL TIME
    </span>

</div>


<div class="grid g4">

    <div class="card stat">

        <div class="l">
            Total Clients
        </div>

        <div
            id="stTotal"
            class="n"
        >
            {{ stat_data['total'] }}
        </div>

    </div>


    <div class="card stat">

        <div class="l">
            Waiting Review
        </div>

        <div
            id="stWaiting"
            class="n"
        >
            {{ stat_data['waiting'] }}
        </div>

    </div>


    <div class="card stat">

        <div class="l">
            Active
        </div>

        <div
            id="stActive"
            class="n"
        >
            {{ stat_data['active'] }}
        </div>

    </div>


    <div class="card stat">

        <div class="l">
            Findings
        </div>

        <div
            id="stFindings"
            class="n"
        >
            {{ stat_data['findings'] }}
        </div>

    </div>

</div>


<div
    class="card"
    style="margin-top:16px"
>

    <div class="spaced">

        <div>

            <div class="kicker">
                Client Queue
            </div>

            <h2 style="margin:5px 0">
                Incoming security requests
            </h2>

        </div>


        <div class="btnrow">

            <input
                id="q"
                style="width:220px"
                placeholder="Search client / target..."
                oninput="filterQueue()"
            >


            <select
                id="f"
                style="width:160px"
                onchange="filterQueue()"
            >

                <option value="">
                    All statuses
                </option>

                {% for status in statuses %}

                <option>
                    {{ status }}
                </option>

                {% endfor %}

            </select>


            <button
                class="btn small"
                onclick="location.reload()"
            >
                ↻ Refresh
            </button>

        </div>

    </div>


    <div
        class="tablewrap"
        style="margin-top:12px"
    >

        <table class="table">

            <thead>

                <tr>

                    <th>
                        #
                    </th>

                    <th>
                        Client
                    </th>

                    <th>
                        Web
                    </th>

                    <th>
                        Target
                    </th>

                    <th>
                        Status
                    </th>

                    <th>
                        Updated
                    </th>

                    <th></th>

                </tr>

            </thead>


            <tbody id="queue">

                {% for client in rows %}

                <tr
                    data-search="{{
                        (
                            client['name']
                            ~' '
                            ~client['email']
                            ~' '
                            ~client['web_name']
                            ~' '
                            ~client['target']
                        )|lower
                    }}"
                    data-status="{{ client['status'] }}"
                >

                    <td>
                        #{{ client['id'] }}
                    </td>

                    <td>

                        <b>
                            {{ client['name'] }}
                        </b>

                        <br>

                        <span class="muted">
                            {{ client['email'] }}
                        </span>

                    </td>

                    <td>
                        {{ client['web_name'] }}
                    </td>

                    <td
                        class="mono"
                        style="max-width:260px"
                    >
                        {{ client['target'] }}
                    </td>

                    <td>

                        <span
                            class="badge {{
                                client['status'].replace(' ','')
                            }}"
                        >
                            {{ client['status'] }}
                        </span>

                    </td>

                    <td class="muted">
                        {{ client['updated_at'] }}
                    </td>

                    <td>

                        <a
                            class="btn small primary"
                            href="{{
                                url_for(
                                    'admin_request',
                                    rid=client['id']
                                )
                            }}"
                        >
                            Open →
                        </a>

                    </td>

                </tr>

                {% else %}

                <tr>

                    <td
                        colspan="7"
                        class="empty"
                    >
                        No clients yet.
                    </td>

                </tr>

                {% endfor %}

            </tbody>

        </table>

    </div>

</div>


<div
    class="grid g2"
    style="margin-top:16px"
>

    <div class="card">

        <div class="spaced">

            <div>

                <div class="kicker">
                    Activity
                </div>

                <h2 style="margin:5px 0">
                    Admin Notifications
                </h2>

            </div>

            <span class="live">
                LIVE
            </span>

        </div>


        <div
            style="
                display:grid;
                gap:8px;
                margin-top:10px
            "
        >

            {% for notification in feed %}

            <div class="notice">

                <b>
                    {{ notification['title'] }}
                </b>

                <div
                    class="muted"
                    style="margin-top:3px"
                >
                    {{ notification['body'] }}
                </div>

                <small class="muted">
                    {{ notification['created_at'] }}
                </small>

            </div>

            {% else %}

            <div class="empty">
                No activity yet.
            </div>

            {% endfor %}

        </div>

    </div>


    <div class="card">

        <div class="spaced">

            <div>

                <div class="kicker">
                    Admin Command Center
                </div>

                <h2 style="margin:5px 0">
                    SOC Terminal
                </h2>

            </div>

            <button
                class="btn small"
                onclick="
                    document
                    .getElementById('cmd')
                    .focus()
                "
            >
                Focus
            </button>

        </div>


        <div
            class="terminal"
            style="margin-top:10px"
        >

            <div class="termhead">

                <span>
                    root@matia-soc:~
                </span>

                <span>
                    AUTHORIZED
                </span>

            </div>


            <div
                id="term"
                class="termbody"
            >

                <div>
                    <span class="green">
                        root@matia-soc:~$
                    </span>

                    /help
                </div>

                <div>
                    Type
                    <b>/help</b>
                    for available commands.
                </div>

            </div>


            <div class="cmdline">

                <span class="green mono">
                    root@matia-soc:~$
                </span>

                <input
                    id="cmd"
                    autocomplete="off"
                    placeholder="/client 12"
                >

            </div>

        </div>

    </div>

</div>


<script>

let baseline =
    JSON.stringify(
        {{
            {
                "t":stat_data["total"],
                "w":stat_data["waiting"],
                "a":stat_data["active"],
                "f":stat_data["findings"],
                "u":latest_updated
            }|tojson
        }}
    );

let adminLast =
    Number(
        localStorage.getItem(
            "matiaAdminNotif"
        ) || 0
    );

let primed = false;

const CSRF =
    {{ csrf_token()|tojson }};


function filterQueue(){

    let query =
        (
            document.getElementById("q")
            .value || ""
        ).toLowerCase();

    let filter =
        document.getElementById("f")
        .value;

    document
        .querySelectorAll(
            "#queue tr[data-search]"
        )
        .forEach(row => {

            row.style.display =
                (
                    !query ||
                    row.dataset.search
                        .includes(query)
                )
                &&
                (
                    !filter ||
                    row.dataset.status === filter
                )
                ? ""
                : "none";

        });

}


async function pollAdmin(){

    try{

        let data =
            await fetch(
                "{{ url_for('api_admin_dashboard') }}"
            ).then(
                response => response.json()
            );

        if (!data.ok){
            return;
        }

        let signature =
            JSON.stringify({
                ...data.stats,
                u:data.latest_updated_at
            });

        if (signature !== baseline){

            baseline = signature;

            if (primed){
                location.reload();
            }

        }


        document
            .getElementById("stTotal")
            .textContent =
            data.stats.total;

        document
            .getElementById("stWaiting")
            .textContent =
            data.stats.waiting;

        document
            .getElementById("stActive")
            .textContent =
            data.stats.active;

        document
            .getElementById("stFindings")
            .textContent =
            data.stats.findings;


        let notificationData =
            await fetch(
                "{{ url_for('api_admin_notifications') }}" +
                "?since=" +
                adminLast
            ).then(
                response => response.json()
            );


        if (
            notificationData.ok &&
            notificationData.notifications.length
        ){

            let newest =
                notificationData
                .notifications[
                    notificationData.notifications.length - 1
                ].id;


            if (!primed){

                adminLast = newest;

                localStorage.setItem(
                    "matiaAdminNotif",
                    adminLast
                );

            }
            else{

                for (
                    const notification
                    of notificationData.notifications
                ){

                    if (
                        notification.id >
                        adminLast
                    ){

                        await notifyMe(
                            notification.title,
                            notification.body
                        );

                        adminLast =
                            notification.id;

                        localStorage.setItem(
                            "matiaAdminNotif",
                            adminLast
                        );

                    }

                }

            }

        }

        primed = true;

    }catch(error){}

}


function commandOutput(text){

    let element =
        document.createElement("div");

    element.innerHTML =
        '<span class="green">' +
        'root@matia-soc:~$' +
        '</span> ' +
        esc(text);

    document
        .getElementById("term")
        .appendChild(element);

}


document
    .getElementById("cmd")
    .addEventListener(
        "keydown",
        async event => {

            if (
                event.key !== "Enter"
            ){
                return;
            }


            let raw =
                event.target.value.trim();

            event.target.value = "";


            if (!raw){
                return;
            }


            commandOutput(raw);


            let parts =
                raw.split(/\s+/);

            let command =
                parts[0].toLowerCase();

            let id =
                Number(parts[1] || 0);


            if (command === "/help"){

                commandOutput(
                    "/clients /pending /active /completed " +
                    "/client <id> /status <id> " +
                    "/findings <id> /report <id> " +
                    "/accept <id> /decline <id> " +
                    "/reopen <id> /start <id> " +
                    "/complete <id> /clear"
                );

                return;

            }


            if (command === "/clear"){

                document
                    .getElementById("term")
                    .innerHTML = "";

                return;

            }


            if (command === "/clients"){

                location.reload();

                return;

            }


            if (
                [
                    "/pending",
                    "/active",
                    "/completed"
                ].includes(command)
            ){

                document
                    .getElementById("q")
                    .value = "";

                document
                    .getElementById("f")
                    .value =
                        command === "/pending"
                        ? "PENDING"
                        : command === "/active"
                        ? "ACCEPTED"
                        : "COMPLETED";

                filterQueue();

                return;

            }


            if (
                id &&
                [
                    "/client",
                    "/status",
                    "/findings",
                    "/report"
                ].includes(command)
            ){

                location.href =
                    "/admin/request/" +
                    id;

                return;

            }


            if (
                id &&
                [
                    "/accept",
                    "/decline",
                    "/reopen",
                    "/start",
                    "/complete"
                ].includes(command)
            ){

                let actionMap = {
                    "/accept":"ACCEPT",
                    "/decline":"DECLINE",
                    "/reopen":"REOPEN",
                    "/start":"START",
                    "/complete":"COMPLETE"
                };

                try{

                    let result =
                        await sendJSON(
                            "/api/admin/request/" +
                            id +
                            "/decision",
                            {
                                method:"POST",
                                body:JSON.stringify({
                                    csrf:CSRF,
                                    action:actionMap[
                                        command
                                    ]
                                })
                            }
                        );

                    commandOutput(
                        result.message
                    );

                    setTimeout(
                        () => location.reload(),
                        450
                    );

                }catch(error){

                    commandOutput(
                        "ERROR: " +
                        error.message
                    );

                }

                return;

            }


            commandOutput(
                "Unknown command. Type /help"
            );

        }
    );


pollAdmin();

setInterval(
    pollAdmin,
    2500
);

</script>

"""

    return page(
        "Admin SOC",
        body,
        rows=rows,
        stat_data=stat_data,
        feed=feed,
        latest_updated=latest_updated,
        statuses=STATUSES,
    )


# ============================================================
# ADMIN DASHBOARD API
# ============================================================

@app.route("/api/admin/dashboard")
@admin_required
def api_admin_dashboard():

    connection = db()

    rows = request_rows(
        connection
    )

    stat_data = stats(
        connection
    )

    latest_updated = connection.execute(
        """
        SELECT COALESCE(MAX(updated_at),'')
        FROM requests
        """
    ).fetchone()[0]

    connection.close()

    return jsonify(
        ok=True,
        stats=stat_data,
        queue=rows,
        latest_updated_at=latest_updated,
    )


# ============================================================
# ADMIN NOTIFICATIONS API
# ============================================================

@app.route("/api/admin/notifications")
@admin_required
def api_admin_notifications():

    since = int(
        request.args.get(
            "since",
            "0"
        ) or 0
    )

    connection = db()

    notifications = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM notifications
            WHERE audience='ADMIN'
              AND id>?
            ORDER BY id
            """,
            (since,),
        ).fetchall()
    ]

    connection.close()

    return jsonify(
        ok=True,
        notifications=notifications
    )


# ============================================================
# ADMIN CLIENT CONTROL CENTER
# ============================================================

@app.route("/admin/request/<int:rid>")
@admin_required
def admin_request(rid):

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if not client:

        connection.close()
        abort(404)

    messages = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
            ORDER BY id
            """,
            (rid,),
        ).fetchall()
    ]

    findings = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (rid,),
        ).fetchall()
    ]

    connection.close()

    counts = {
        severity:
            sum(
                finding["severity"] == severity
                for finding in findings
            )
        for severity in SEVERITIES
    }

    body = r"""

<div
    class="spaced"
    style="margin:24px 0"
>

    <div>

        <div class="eyebrow">
            CLIENT CONTROL CENTER
        </div>

        <h1 style="margin:6px 0">
            #{{ client['id'] }}
            ·
            {{ client['name'] }}
        </h1>

        <div class="muted">
            {{ client['web_name'] }}
            ·
            {{ client['email'] }}
        </div>

    </div>


    <div class="btnrow">

        <a
            class="btn"
            href="{{ url_for('admin_dashboard') }}"
        >
            ← Queue
        </a>

        <a
            class="btn"
            href="{{
                url_for(
                    'admin_report',
                    rid=client['id']
                )
            }}"
        >
            📄 Report
        </a>

        <span
            id="statusText"
            class="badge {{ client['status'].replace(' ','') }}"
        >
            {{ client['status'] }}
        </span>

    </div>

</div>


<div class="card">

    <div class="grid g3">

        <div>

            <div class="kicker">
                Target
            </div>

            <div
                class="mono"
                style="
                    margin-top:6px;
                    word-break:break-all
                "
            >
                {{ client['target'] }}
            </div>

        </div>


        <div>

            <div class="kicker">
                Scope
            </div>

            <div
                class="muted"
                style="
                    white-space:pre-wrap;
                    margin-top:6px
                "
            >
                {{ client['scope'] }}
            </div>

        </div>


        <div>

            <div class="kicker">
                Request Meta
            </div>

            <div
                class="muted"
                style="margin-top:6px"
            >

                Created:
                {{ client['created_at'] }}

                <br>

                IP:
                {{
                    client['client_ip']
                    or
                    'hidden'
                }}

            </div>

        </div>

    </div>


    <div
        class="btnrow"
        style="margin-top:15px"
    >

        {% if client['status']
            not in ['ACCEPTED',
                    'IN PROGRESS',
                    'COMPLETED'] %}

        <button
            class="btn green"
            onclick="decision('ACCEPT')"
        >
            ✓ ACCEPT CLIENT
        </button>

        {% endif %}


        {% if client['status']
            not in ['DECLINED',
                    'COMPLETED'] %}

        <button
            class="btn red"
            onclick="decision('DECLINE')"
        >
            ✕ DECLINE
        </button>

        {% endif %}


        {% if client['status']=='ACCEPTED' %}

        <button
            class="btn blue"
            onclick="decision('START')"
        >
            ▶ START ASSESSMENT
        </button>

        {% endif %}


        {% if client['status']=='IN PROGRESS' %}

        <button
            class="btn primary"
            onclick="decision('COMPLETE')"
        >
            ✓ MARK COMPLETED
        </button>

        {% endif %}


        {% if client['status']=='DECLINED' %}

        <button
            class="btn yellow"
            onclick="decision('REOPEN')"
        >
            ↻ REOPEN
        </button>

        {% endif %}

    </div>

</div>


<div
    class="grid g2"
    style="margin-top:16px"
>


    <div class="card">

        <div class="spaced">

            <h2>
                💬 LIVE CHAT
            </h2>

            <span class="live">
                CLIENT LINKED
            </span>

        </div>


        <div class="chat">

            <div
                id="adminMsgs"
                class="msgs"
            >

                {% for message in messages %}

                <div
                    class="msg
                    {% if message['sender']=='ADMIN' %}
                    me
                    {% endif %}"
                >

                    <div class="meta">

                        {{ message['sender'] }}
                        ·
                        {{ message['created_at'] }}

                    </div>

                    <div
                        style="white-space:pre-wrap"
                    >
                        {{ message['message'] }}
                    </div>

                </div>

                {% endfor %}

            </div>


            <div class="chatinput">

                <input
                    id="adminInput"
                    placeholder="Reply to client..."
                    maxlength="4000"
                >

                <button
                    class="btn primary"
                    onclick="sendAdmin()"
                >
                    Send
                </button>

            </div>

        </div>

    </div>


    <div>


        <div class="card">

            <div class="spaced">

                <h2 style="margin:0">
                    🔎 Findings
                </h2>

                <span>
                    {{ findings|length }}
                    total
                </span>

            </div>


            {% for finding in findings %}

            <div
                class="notice"
                style="margin-top:9px"
            >

                <div class="spaced">

                    <b>
                        {{ finding['title'] }}
                    </b>

                    <span
                        class="sev sev-{{ finding['severity'] }}"
                    >
                        {{ finding['severity'] }}
                    </span>

                </div>

                <div
                    class="muted"
                    style="
                        margin-top:5px;
                        white-space:pre-wrap
                    "
                >
                    {{ finding['description'] }}
                </div>

            </div>

            {% else %}

            <div class="empty">
                No findings yet.
            </div>

            {% endfor %}

        </div>


        <div
            class="card"
            style="margin-top:16px"
        >

            <div class="kicker">
                PUBLISH FINDING
            </div>

            <h2
                style="margin:6px 0 14px"
            >
                Add evidence to the report
            </h2>


            <form id="findingForm">


                <div class="field">

                    <label>
                        Title
                    </label>

                    <input
                        name="title"
                        required
                        maxlength="200"
                        placeholder="Authentication control issue"
                    >

                </div>


                <div class="field">

                    <label>
                        Severity
                    </label>

                    <select name="severity">

                        {% for severity in severities %}

                        <option>
                            {{ severity }}
                        </option>

                        {% endfor %}

                    </select>

                </div>


                <div class="field">

                    <label>
                        Description
                    </label>

                    <textarea
                        name="description"
                        required
                        maxlength="6000"
                    ></textarea>

                </div>


                <div class="field">

                    <label>
                        Evidence
                    </label>

                    <textarea
                        name="evidence"
                        maxlength="6000"
                    ></textarea>

                </div>


                <div class="field">

                    <label>
                        Recommendation
                    </label>

                    <textarea
                        name="recommendation"
                        maxlength="4000"
                    ></textarea>

                </div>


                <button
                    class="btn primary"
                >
                    Publish Finding
                </button>

            </form>

        </div>

    </div>

</div>


<script>

const RID =
    {{ client['id'] }};

const CSRF =
    {{ csrf_token()|tojson }};

let last =
    Number(
        '{{ messages[-1]["id"] if messages else 0 }}'
    );

let signature =
    {{ client['updated_at']|tojson }};


async function decision(action){

    try{

        let result =
            await sendJSON(
                `/api/admin/request/${RID}/decision`,
                {
                    method:"POST",

                    body:JSON.stringify({
                        csrf:CSRF,
                        action:action
                    })
                }
            );

        toast(
            result.message
        );

        setTimeout(
            () => location.reload(),
            400
        );

    }catch(error){

        toast(
            error.message
        );

    }

}


function addAdmin(message){

    let element =
        document.createElement("div");

    element.className =
        "msg " +
        (
            message.sender === "ADMIN"
            ? "me"
            : ""
        );

    element.innerHTML =
        '<div class="meta">' +
        esc(message.sender) +
        ' · ' +
        esc(message.created_at) +
        '</div>' +
        '<div style="white-space:pre-wrap">' +
        esc(message.message) +
        '</div>';

    let box =
        document.getElementById(
            "adminMsgs"
        );

    box.appendChild(element);

    box.scrollTop =
        box.scrollHeight;

}


async function pollAdminChat(){

    try{

        let data =
            await fetch(
                `/api/admin/request/${RID}?since=${last}`
            ).then(
                response => response.json()
            );

        if (!data.ok){
            return;
        }


        for (
            const message
            of data.messages || []
        ){

            last =
                Math.max(
                    last,
                    message.id
                );

            addAdmin(message);


            if (
                message.sender === "CLIENT"
            ){

                await notifyMe(
                    "Client message",
                    message.message
                );

            }

        }


        if (
            data.updated_at !==
            signature
        ){

            signature =
                data.updated_at;

            if (
                data.status !==
                document
                .getElementById(
                    "statusText"
                )
                .textContent
                .trim()
            ){

                location.reload();

            }

        }

    }catch(error){}

}


async function sendAdmin(){

    let input =
        document.getElementById(
            "adminInput"
        );

    let text =
        input.value.trim();

    if (!text){
        return;
    }


    try{

        await sendJSON(
            `/admin/request/${RID}/message`,
            {
                method:"POST",

                body:JSON.stringify({
                    csrf:CSRF,
                    message:text
                })
            }
        );

        input.value = "";

        await pollAdminChat();

    }catch(error){

        toast(
            error.message
        );

    }

}


document
    .getElementById("adminInput")
    .addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Enter"
            ){

                event.preventDefault();

                sendAdmin();

            }

        }
    );


document
    .getElementById("findingForm")
    .addEventListener(
        "submit",
        async event => {

            event.preventDefault();

            let form =
                new FormData(
                    event.target
                );


            try{

                let result =
                    await sendJSON(
                        `/admin/request/${RID}/finding`,
                        {
                            method:"POST",

                            body:JSON.stringify({
                                csrf:CSRF,
                                title:form.get("title"),
                                severity:form.get("severity"),
                                description:form.get("description"),
                                evidence:form.get("evidence"),
                                recommendation:form.get("recommendation")
                            })
                        }
                    );

                toast(
                    result.message
                );

                event.target.reset();

                setTimeout(
                    () => location.reload(),
                    400
                );

            }catch(error){

                toast(
                    error.message
                );

            }

        }
    );


pollAdminChat();

setInterval(
    pollAdminChat,
    2000
);

</script>

"""

    return page(
        f"Client #{rid}",
        body,
        client=client,
        messages=messages,
        findings=findings,
        severities=SEVERITIES,
        counts=counts,
    )


# ============================================================
# ADMIN CLIENT CHAT API
# ============================================================

@app.route(
    "/api/admin/request/<int:rid>"
)
@admin_required
def api_admin_request(rid):

    since = int(
        request.args.get(
            "since",
            "0"
        ) or 0
    )

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()

    if not client:

        connection.close()

        return jsonify(
            ok=False
        ), 404

    messages = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
              AND id>?
            ORDER BY id
            """,
            (
                rid,
                since,
            ),
        ).fetchall()
    ]

    connection.close()

    return jsonify(
        ok=True,
        status=client["status"],
        updated_at=client["updated_at"],
        messages=messages,
    )


# ============================================================
# ADMIN DECISION API
# ============================================================

@app.route(
    "/api/admin/request/<int:rid>/decision",
    methods=["POST"]
)
@admin_required
def decision(rid):

    data = request.get_json(
        silent=True
    ) or {}

    if not check_csrf(
        data.get("csrf")
    ):

        return jsonify(
            ok=False,
            error="Security check failed"
        ), 403


    action = clean(
        data.get("action"),
        30
    ).upper()


    transitions = {

        "ACCEPT": (
            "ACCEPTED",
            "Your security request has been ACCEPTED. "
            "The secure chat with the administrator is now open."
        ),

        "DECLINE": (
            "DECLINED",
            "Your security request has been DECLINED. "
            "The administrator has closed this request."
        ),

        "REOPEN": (
            "PENDING",
            "Your security request has been REOPENED "
            "and returned to the review queue."
        ),

        "START": (
            "IN PROGRESS",
            "Your security assessment is now IN PROGRESS."
        ),

        "COMPLETE": (
            "COMPLETED",
            "Your security assessment has been marked COMPLETED."
        ),

    }


    if action not in transitions:

        return jsonify(
            ok=False,
            error="Unknown action"
        ), 400


    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()


    if not client:

        connection.close()

        return jsonify(
            ok=False,
            error="Client not found"
        ), 404


    new_status, message = \
        transitions[action]

    timestamp = now()


    connection.execute(
        """
        UPDATE requests
        SET status=?,
            updated_at=?
        WHERE id=?
        """,
        (
            new_status,
            timestamp,
            rid,
        ),
    )


    system_message(
        connection,
        rid,
        message
    )


    notify(
        connection,
        rid,
        "CLIENT",
        "STATUS",
        "Security request updated",
        message,
    )


    notify(
        connection,
        rid,
        "ADMIN",
        "STATUS",
        f"Client #{rid} status",
        new_status,
    )


    connection.commit()
    connection.close()


    return jsonify(
        ok=True,
        status=new_status,
        message=message
    )


# ============================================================
# ADMIN SEND MESSAGE
# ============================================================

@app.route(
    "/admin/request/<int:rid>/message",
    methods=["POST"]
)
@admin_required
def admin_message(rid):

    data = request.get_json(
        silent=True
    ) or {}


    if not check_csrf(
        data.get("csrf")
    ):

        return jsonify(
            ok=False,
            error="Security check failed"
        ), 403


    message = clean(
        data.get("message"),
        4000
    )

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()


    if not client:

        connection.close()

        return jsonify(
            ok=False,
            error="Client not found"
        ), 404


    if client["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED",
    ):

        connection.close()

        return jsonify(
            ok=False,
            error="Chat is locked for this request"
        ), 403


    if not message:

        connection.close()

        return jsonify(
            ok=False,
            error="Message is empty"
        ), 400


    timestamp = now()


    connection.execute(
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
            rid,
            "ADMIN",
            message,
            timestamp,
        ),
    )


    connection.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            timestamp,
            rid,
        ),
    )


    notify(
        connection,
        rid,
        "CLIENT",
        "MESSAGE",
        "New message from administrator",
        message,
    )


    connection.commit()
    connection.close()


    return jsonify(ok=True)


# ============================================================
# ADMIN FINDING
# ============================================================

@app.route(
    "/admin/request/<int:rid>/finding",
    methods=["POST"]
)
@admin_required
def finding(rid):

    data = request.get_json(
        silent=True
    ) or {}


    if not check_csrf(
        data.get("csrf")
    ):

        return jsonify(
            ok=False,
            error="Security check failed"
        ), 403


    title = clean(
        data.get("title"),
        200
    )

    severity = clean(
        data.get("severity"),
        20
    ).upper()

    description = clean(
        data.get("description"),
        6000
    )

    evidence = clean(
        data.get("evidence"),
        6000
    )

    recommendation = clean(
        data.get("recommendation"),
        4000
    )


    if (
        not title
        or severity not in SEVERITIES
        or not description
    ):

        return jsonify(
            ok=False,
            error="Title, severity and description are required"
        ), 400


    connection = db()

    client = connection.execute(
        """
        SELECT id
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()


    if not client:

        connection.close()

        return jsonify(
            ok=False,
            error="Client not found"
        ), 404


    timestamp = now()


    connection.execute(
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
            rid,
            title,
            severity,
            description,
            evidence,
            recommendation,
            timestamp,
        ),
    )


    connection.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            timestamp,
            rid,
        ),
    )


    notify(
        connection,
        rid,
        "CLIENT",
        "FINDING",
        "New finding published",
        f"{severity}: {title}",
    )


    connection.commit()
    connection.close()


    return jsonify(
        ok=True,
        message="Finding published and added to the report"
    )


# ============================================================
# ADMIN REPORT
# ============================================================

@app.route(
    "/admin/report/<int:rid>"
)
@admin_required
def admin_report(rid):

    connection = db()

    client = connection.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (rid,),
    ).fetchone()


    if not client:

        connection.close()

        abort(404)


    findings = [
        dict(row)
        for row in connection.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (rid,),
        ).fetchall()
    ]


    connection.close()


    counts = {
        severity:
            sum(
                finding["severity"] == severity
                for finding in findings
            )
        for severity in SEVERITIES
    }


    body = r"""

<div
    class="spaced"
    style="margin:25px 0"
>

    <div>

        <div class="eyebrow">
            ADMIN REPORT
        </div>

        <h1 style="margin:7px 0">
            #{{ client['id'] }}
            ·
            {{ client['web_name'] }}
        </h1>

        <div class="muted">
            {{ client['target'] }}
        </div>

    </div>


    <a
        class="btn"
        href="{{
            url_for(
                'admin_request',
                rid=client['id']
            )
        }}"
    >
        ← Control Center
    </a>

</div>


<div class="grid g4">

    {% for severity in severities %}

    <div class="card stat">

        <div class="l">
            {{ severity }}
        </div>

        <div class="n">
            {{ counts[severity] }}
        </div>

    </div>

    {% endfor %}

</div>


<div
    class="card"
    style="margin-top:16px"
>

    <div class="kicker">
        Client / Scope
    </div>

    <p class="muted">
        {{ client['name'] }}
        ·
        {{ client['email'] }}
    </p>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{ client['scope'] }}
    </p>

</div>


{% for finding in findings %}

<div
    class="card"
    style="margin-top:12px"
>

    <div class="spaced">

        <h2 style="margin:0">
            {{ finding['title'] }}
        </h2>

        <span
            class="sev sev-{{ finding['severity'] }}"
        >
            {{ finding['severity'] }}
        </span>

    </div>


    <div class="sep"></div>


    <div class="kicker">
        Description
    </div>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{ finding['description'] }}
    </p>


    <div class="kicker">
        Evidence
    </div>

    <div
        class="mono"
        style="
            white-space:pre-wrap;
            background:#04070b;
            border:1px solid #142131;
            padding:13px;
            border-radius:12px
        "
    >
        {{
            finding['evidence']
            or
            'No evidence supplied.'
        }}
    </div>


    <div
        class="kicker"
        style="margin-top:13px"
    >
        Recommendation
    </div>

    <p
        class="muted"
        style="white-space:pre-wrap"
    >
        {{
            finding['recommendation']
            or
            'No recommendation supplied.'
        }}
    </p>

</div>


{% else %}

<div
    class="card empty"
    style="margin-top:16px"
>
    No findings published.
</div>

{% endfor %}

"""

    return page(
        f"Admin Report #{rid}",
        body,
        client=client,
        findings=findings,
        counts=counts,
        severities=SEVERITIES,
    )


# ============================================================
# ERRORS
# ============================================================

@app.errorhandler(404)
def error_404(_):

    return page(
        "404",
        r"""
        <div
            class="card center"
            style="
                max-width:600px;
                margin:80px auto
            "
        >

            <div class="eyebrow">
                404
            </div>

            <h1>
                Not found
            </h1>

            <p class="muted">
                This resource does not exist.
            </p>

            <a
                class="btn primary"
                href="{{ url_for('home') }}"
            >
                Home
            </a>

        </div>
        """
    ), 404


@app.errorhandler(403)
def error_403(_):

    return page(
        "403",
        r"""
        <div
            class="card center"
            style="
                max-width:600px;
                margin:80px auto
            "
        >

            <div class="eyebrow">
                403
            </div>

            <h1>
                Access denied
            </h1>

            <p class="muted">
                Authorized admin access is required.
            </p>

        </div>
        """
    ), 403


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "10000"
            )
        ),
        debug=False,
    )
