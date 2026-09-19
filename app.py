import os
import sqlite3
import secrets
import hmac
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
    flash,
)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

app.secret_key = os.getenv(
    "MATIA_SECRET_KEY",
    "CHANGE-ME-IN-RENDER"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "COOKIE_SECURE",
        "true"
    ).lower() == "true",
)

ADMIN_EMAIL = os.getenv(
    "MATIA_ADMIN_EMAIL",
    "kleimatia1@gmail.com"
).strip().lower()

ADMIN_PASSWORD = os.getenv(
    "MATIA_ADMIN_PASSWORD",
    ""
).strip()

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB_PATH = os.path.join(
    BASE_DIR,
    "matia_security.db"
)


# ============================================================
# CSS
# ============================================================

CSS = r'''
:root{
    --bg:#060812;
    --panel:#0d1220;
    --panel2:#111827;
    --line:#24304a;
    --text:#e8eefc;
    --muted:#8d9ab5;
    --cyan:#00e5ff;
    --green:#28e38b;
    --red:#ff5277;
    --yellow:#ffd166;
    --purple:#9b7bff;
}

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at 20% 0%,
            #10243a 0,
            #060812 35%,
            #03050a 100%
        );
    color:var(--text);
    font-family:
        Inter,
        Segoe UI,
        Arial,
        sans-serif;
    min-height:100vh;
}

a{
    color:var(--cyan);
    text-decoration:none;
}

button,
input,
textarea,
select{
    font:inherit;
}

button{
    cursor:pointer;
}

.nav{
    position:sticky;
    top:0;
    z-index:20;
    background:rgba(5,8,16,.86);
    backdrop-filter:blur(16px);
    border-bottom:1px solid var(--line);
    padding:15px 5%;
    display:flex;
    align-items:center;
    justify-content:space-between;
}

.brand{
    font-weight:900;
    letter-spacing:1.5px;
}

.brand span{
    color:var(--cyan);
}

.navlinks{
    display:flex;
    gap:14px;
    align-items:center;
}

.navlinks a,
.navlinks button{
    color:var(--muted);
    background:none;
    border:0;
}

.wrap{
    width:min(1180px,92%);
    margin:35px auto;
}

.hero{
    padding:28px 0;
}

.hero h1{
    font-size:clamp(30px,5vw,56px);
    margin:0 0 10px;
}

.hero p{
    color:var(--muted);
    max-width:760px;
}

.grid{
    display:grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(240px,1fr)
        );
    gap:18px;
}

.card{
    background:
        linear-gradient(
            145deg,
            rgba(17,24,39,.96),
            rgba(8,12,23,.96)
        );
    border:1px solid var(--line);
    border-radius:18px;
    padding:20px;
    box-shadow:0 14px 50px #0005;
}

.stat{
    font-size:32px;
    font-weight:900;
}

.muted{
    color:var(--muted);
}

.small{
    font-size:13px;
}

.form{
    display:grid;
    gap:14px;
}

.row{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:14px;
}

.field label{
    display:block;
    font-size:13px;
    color:var(--muted);
    margin-bottom:7px;
}

.field input,
.field textarea,
.field select{
    width:100%;
    background:#070b15;
    border:1px solid var(--line);
    color:var(--text);
    border-radius:12px;
    padding:12px;
    outline:none;
}

.field textarea{
    min-height:120px;
    resize:vertical;
}

.field input:focus,
.field textarea:focus,
.field select:focus{
    border-color:var(--cyan);
    box-shadow:0 0 0 3px #00e5ff18;
}

.btn{
    border:1px solid var(--line);
    border-radius:11px;
    padding:11px 15px;
    background:#111827;
    color:var(--text);
    font-weight:800;
}

.btn.primary{
    background:var(--cyan);
    color:#001018;
    border-color:var(--cyan);
}

.btn.green{
    background:var(--green);
    color:#00130b;
    border-color:var(--green);
}

.btn.red{
    background:#3a101c;
    color:#ff9ab0;
    border-color:#702238;
}

.btn.yellow{
    background:#332b0c;
    color:#ffe8a0;
    border-color:#695b19;
}

.btn.purple{
    background:#21183e;
    color:#c9b8ff;
    border-color:#4f3b8e;
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:9px;
}

.status{
    display:inline-flex;
    padding:6px 10px;
    border-radius:999px;
    font-size:12px;
    font-weight:900;
    border:1px solid var(--line);
}

.pending{
    color:var(--yellow);
}

.accepted{
    color:var(--cyan);
}

.in-progress{
    color:var(--purple);
}

.completed{
    color:var(--green);
}

.declined{
    color:var(--red);
}

.tablewrap{
    overflow:auto;
}

.table{
    width:100%;
    border-collapse:collapse;
}

.table th,
.table td{
    text-align:left;
    padding:13px;
    border-bottom:1px solid var(--line);
    white-space:nowrap;
}

.table th{
    color:var(--muted);
    font-size:12px;
}

.notice{
    padding:12px 14px;
    border:1px solid #244a5a;
    background:#071922;
    border-radius:12px;
    margin-bottom:15px;
}

.error{
    border-color:#6d2336;
    background:#220b13;
    color:#ffb0bf;
}

.chat{
    display:flex;
    flex-direction:column;
    gap:10px;
    max-height:440px;
    overflow:auto;
    margin-bottom:12px;
}

.msg{
    padding:12px;
    border:1px solid var(--line);
    border-radius:13px;
    background:#0a0f1b;
}

.msg.admin{
    border-color:#244c62;
}

.msg.client{
    border-color:#3d316a;
}

.msg.system{
    border-color:#4e4b1c;
}

.msg b{
    font-size:12px;
}

.finding{
    border:1px solid var(--line);
    border-radius:14px;
    padding:15px;
    margin:10px 0;
}

.sev{
    font-weight:900;
}

.sev-HIGH,
.sev-CRITICAL{
    color:#ff6688;
}

.sev-MEDIUM{
    color:var(--yellow);
}

.sev-LOW{
    color:var(--cyan);
}

.sev-INFO{
    color:var(--muted);
}

.toastbox{
    position:fixed;
    right:18px;
    bottom:18px;
    z-index:100;
    display:grid;
    gap:10px;
    width:min(380px,calc(100% - 36px));
}

.toast{
    background:#0c1422;
    border:1px solid var(--cyan);
    padding:14px;
    border-radius:14px;
    box-shadow:0 12px 45px #0009;
}

.pill{
    display:inline-block;
    padding:4px 8px;
    border-radius:999px;
    background:#111827;
    color:var(--muted);
    font-size:11px;
}

.check{
    display:flex;
    gap:9px;
    align-items:flex-start;
}

.footer{
    text-align:center;
    color:var(--muted);
    padding:45px 0;
}

.login{
    width:min(480px,100%);
    margin:70px auto;
}

.mono{
    font-family:
        ui-monospace,
        SFMono-Regular,
        Consolas,
        monospace;
    white-space:pre-wrap;
}

.notifbar{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:12px;
    flex-wrap:wrap;
}

.empty{
    padding:30px;
    text-align:center;
    color:var(--muted);
}

@media(max-width:700px){
    .row{
        grid-template-columns:1fr;
    }

    .nav{
        padding:13px 4%;
    }

    .navlinks{
        gap:8px;
    }

    .wrap{
        margin-top:22px;
    }

    .table th,
    .table td{
        padding:10px;
    }
}
'''


# ============================================================
# SHELL
# ============================================================

SHELL = r'''
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<meta
    name="theme-color"
    content="#060812"
>

<title>
    {{ title }} · MATIA // SECURITY CHECK
</title>

<style>
{{ css|safe }}
</style>

</head>

<body>

<nav class="nav">

<a
    class="brand"
    href="{{ url_for('home') }}"
>
    MATIA
    <span>// SECURITY CHECK</span>
</a>

<div class="navlinks">

<a href="{{ url_for('new_request') }}">
    Request
</a>

{% if session.get('admin') %}

<a href="{{ url_for('admin_dashboard') }}">
    Admin
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

</nav>

<main class="wrap">

{{ content|safe }}

</main>

<div
    id="toastbox"
    class="toastbox"
></div>

<footer class="footer">
    Authorized security assessments only
    · MATIA // SECURITY CHECK
</footer>

</body>
</html>
'''


# ============================================================
# HOME
# ============================================================

HOME = r'''
<section class="hero">

<span class="pill">
    AUTHORIZED SECURITY ASSESSMENT PORTAL
</span>

<h1>
    MATIA
    <span style="color:var(--cyan)">
        // SECURITY CHECK
    </span>
</h1>

<p>
    Submit a website you own or are explicitly authorized
    to test. Track the request, communicate securely with
    the administrator, and receive published findings in
    one portal.
</p>

<div class="actions">

<a
    class="btn primary"
    href="{{ url_for('new_request') }}"
>
    Start Security Request →
</a>

<a
    class="btn"
    href="{{ url_for('admin_login') }}"
>
    Admin Console
</a>

</div>

</section>

<div class="grid">

<div class="card">
    <div class="stat">01</div>
    <div class="muted">
        Submit target + scope
    </div>
</div>

<div class="card">
    <div class="stat">02</div>
    <div class="muted">
        Admin reviews request
    </div>
</div>

<div class="card">
    <div class="stat">03</div>
    <div class="muted">
        Secure chat opens after approval
    </div>
</div>

<div class="card">
    <div class="stat">04</div>
    <div class="muted">
        Published findings + report
    </div>
</div>

</div>
'''


# ============================================================
# REQUEST FORM
# ============================================================

REQUEST_FORM = r'''
<div class="card">

<h1>
    New Security Request
</h1>

<p class="muted">
    Only submit targets you own or have explicit
    authorization to assess.
</p>

{% with messages=get_flashed_messages() %}

{% for m in messages %}

<div class="notice error">
    {{ m }}
</div>

{% endfor %}

{% endwith %}

<form
    class="form"
    method="post"
>

<div class="row">

<div class="field">

<label>
    Your Name
</label>

<input
    name="name"
    required
    maxlength="100"
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

</div>


<div class="row">

<div class="field">

<label>
    Web Name
</label>

<input
    name="web_name"
    required
    maxlength="120"
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
    maxlength="500"
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
    maxlength="5000"
    placeholder="Example: public website only; no DoS; no third-party services."
></textarea>

</div>


<label class="check">

<input
    type="checkbox"
    name="authorized"
    value="yes"
    required
>

<span>
    I confirm that I own this target or have explicit
    authorization to request a security assessment.
</span>

</label>


<button
    class="btn primary"
    type="submit"
>
    Submit Security Request
</button>

</form>

</div>
'''


# ============================================================
# ADMIN LOGIN
# ============================================================

LOGIN = r'''
<div class="login card">

<h1>
    Admin Console
</h1>

<p class="muted">
    Authorized administrator access.
</p>

{% with messages=get_flashed_messages() %}

{% for m in messages %}

<div class="notice error">
    {{ m }}
</div>

{% endfor %}

{% endwith %}

<form
    class="form"
    method="post"
>

<div class="field">

<label>
    Email
</label>

<input
    name="email"
    type="email"
    value="{{ admin_email }}"
    readonly
    autocomplete="username"
>

</div>


<div class="field">

<label>
    Password
</label>

<input
    name="password"
    type="password"
    required
    autocomplete="current-password"
>

</div>


<button
    class="btn primary"
>
    Sign in
</button>

</form>

<p class="small muted">
    Password is loaded from MATIA_ADMIN_PASSWORD
    in the server environment.
</p>

</div>
'''


# ============================================================
# ADMIN DASHBOARD
# ============================================================

ADMIN_DASH = r'''
<div class="hero">

<div class="notifbar">

<div>

<span class="pill">
    ADMIN CONSOLE ONLINE
</span>

<h1>
    Security Operations
</h1>

<p class="muted">
    Review requests, open one client at a time,
    manage assessments and receive real browser
    notifications.
</p>

</div>

<button
    class="btn"
    onclick="enableNotifications()"
>
    🔔 Enable Notifications
</button>

</div>

</div>


<div class="grid">

<div class="card">

<div
    id="total"
    class="stat"
>
    {{ stats.total }}
</div>

<div class="muted">
    Total Clients
</div>

</div>


<div class="card">

<div
    id="waiting"
    class="stat"
>
    {{ stats.waiting }}
</div>

<div class="muted">
    Waiting Review
</div>

</div>


<div class="card">

<div
    id="active"
    class="stat"
>
    {{ stats.active }}
</div>

<div class="muted">
    Active
</div>

</div>


<div class="card">

<div
    id="findings"
    class="stat"
>
    {{ stats.findings }}
</div>

<div class="muted">
    Findings
</div>

</div>

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
    Client Queue
</h2>

<div class="tablewrap">

<table class="table">

<thead>

<tr>

<th>ID</th>
<th>Client</th>
<th>Website</th>
<th>Target</th>
<th>Status</th>
<th>Created</th>
<th></th>

</tr>

</thead>

<tbody id="queue">

{% for r in rows %}

<tr>

<td>
    #{{ r.id }}
</td>

<td>
    {{ r.name|e }}
    <br>
    <span class="small muted">
        {{ r.email|e }}
    </span>
</td>

<td>
    {{ r.web_name|e }}
</td>

<td>
    {{ r.target|e }}
</td>

<td>

<span
    class="status
    {{ r.status|lower|replace(' ','-') }}"
>
    {{ r.status }}
</span>

</td>

<td class="small">
    {{ r.created_at }}
</td>

<td>

<a
    class="btn"
    href="{{ url_for('admin_request', rid=r.id) }}"
>
    Open Client →
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


<script>

const adminLastKey =
    'matia_admin_last_notification';

let adminBaseline = null;


async function enableNotifications(){

    if(!('Notification' in window)){

        toast(
            'This browser does not support notifications'
        );

        return;
    }

    const p =
        await Notification.requestPermission();

    toast(
        p === 'granted'
        ? 'Browser notifications enabled'
        : 'Notification permission was not granted'
    );
}


function toast(t){

    const box =
        document.getElementById('toastbox');

    const x =
        document.createElement('div');

    x.className = 'toast';

    x.textContent = t;

    box.appendChild(x);

    setTimeout(
        () => x.remove(),
        5000
    );
}


function notify(n){

    if(
        'Notification' in window &&
        Notification.permission === 'granted'
    ){

        new Notification(
            n.title,
            {
                body:n.body,
                tag:'matia-'+n.id
            }
        );

    }

    toast(
        n.title + ': ' + n.body
    );
}


async function pollAdmin(){

    try{

        const r =
            await fetch(
                '{{ url_for("api_admin_dashboard") }}?t='
                + Date.now(),
                {
                    cache:'no-store'
                }
            );

        const d =
            await r.json();

        document.getElementById('total')
            .textContent = d.stats.total;

        document.getElementById('waiting')
            .textContent = d.stats.waiting;

        document.getElementById('active')
            .textContent = d.stats.active;

        document.getElementById('findings')
            .textContent = d.stats.findings;


        if(adminBaseline === null){

            adminBaseline =
                d.latest_notification_id;

            localStorage.setItem(
                adminLastKey,
                String(adminBaseline)
            );

        }
        else if(
            d.latest_notification_id >
            Number(
                localStorage.getItem(
                    adminLastKey
                ) || 0
            )
        ){

            const n =
                await fetch(
                    '{{ url_for("api_admin_notifications") }}?since='
                    + Number(
                        localStorage.getItem(
                            adminLastKey
                        ) || 0
                    )
                    + '&t='
                    + Date.now(),
                    {
                        cache:'no-store'
                    }
                )
                .then(x => x.json());


            for(
                const item of n.notifications
            ){

                if(
                    item.id >
                    Number(
                        localStorage.getItem(
                            adminLastKey
                        ) || 0
                    )
                ){

                    notify(item);

                }

                localStorage.setItem(
                    adminLastKey,
                    String(item.id)
                );

            }

        }

    }
    catch(e){

    }

}


setInterval(
    pollAdmin,
    2500
);

pollAdmin();

</script>
'''


# ============================================================
# ADMIN DETAIL
# ============================================================

ADMIN_DETAIL = r'''
<div class="actions">

<a
    class="btn"
    href="{{ url_for('admin_dashboard') }}"
>
    ← Queue
</a>

<a
    class="btn"
    href="{{ url_for('admin_report', rid=r.id) }}"
>
    Full Report
</a>

<button
    class="btn"
    onclick="enableNotifications()"
>
    🔔 Notifications
</button>

</div>


<div class="grid">

<div class="card">

<span class="pill">
    REQUEST #{{ r.id }}
</span>

<h1>
    {{ r.web_name|e }}
</h1>

<p class="muted">
    {{ r.target|e }}
</p>

<p>

<span
    class="status
    {{ r.status|lower|replace(' ','-') }}"
>
    {{ r.status }}
</span>

</p>

<p>
    <b>Client:</b>
    {{ r.name|e }}
    ·
    {{ r.email|e }}
</p>

<p>
    <b>Scope:</b>
    <br>
    {{ r.scope|e }}
</p>

<p class="small muted">
    Created {{ r.created_at }}
    ·
    Updated {{ r.updated_at }}
</p>


<div class="actions">

{% if r.status == 'PENDING' %}

<form
    method="post"
    action="{{ url_for('admin_decision',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>

<input
    type="hidden"
    name="action"
    value="ACCEPT"
>

<button
    class="btn green"
>
    ✓ Accept Client
</button>

</form>


<form
    method="post"
    action="{{ url_for('admin_decision',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>

<input
    type="hidden"
    name="action"
    value="DECLINE"
>

<button
    class="btn red"
>
    ✕ Decline
</button>

</form>


{% elif r.status == 'ACCEPTED' %}

<form
    method="post"
    action="{{ url_for('admin_decision',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>

<input
    type="hidden"
    name="action"
    value="START"
>

<button
    class="btn primary"
>
    ▶ Start Assessment
</button>

</form>


{% elif r.status == 'IN PROGRESS' %}

<form
    method="post"
    action="{{ url_for('admin_decision',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>

<input
    type="hidden"
    name="action"
    value="COMPLETE"
>

<button
    class="btn green"
>
    ✓ Mark Completed
</button>

</form>


{% elif r.status == 'DECLINED' %}

<form
    method="post"
    action="{{ url_for('admin_decision',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>

<input
    type="hidden"
    name="action"
    value="REOPEN"
>

<button
    class="btn yellow"
>
    ↻ Reopen
</button>

</form>

{% endif %}

</div>


<p class="small muted">

Client portal:

<a
    href="{{ client_link }}"
    target="_blank"
>
    open client portal
</a>

</p>

</div>


<div class="card">

<h2>
    Secure Chat
</h2>

<div
    id="chat"
    class="chat"
>

{% for m in messages %}

<div
    class="msg {{ m.sender|lower }}"
>

<b>
    {{ m.sender }}
</b>

<div>
    {{ m.message|e }}
</div>

<span class="small muted">
    {{ m.created_at }}
</span>

</div>

{% else %}

<div class="empty">
    No messages yet.
</div>

{% endfor %}

</div>


{% if r.status in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

<form
    id="chatForm"
    class="actions"
>

<input
    id="chatInput"
    style="
        flex:1;
        min-width:220px;
        background:#070b15;
        border:1px solid var(--line);
        border-radius:12px;
        color:var(--text);
        padding:12px
    "
    maxlength="4000"
    placeholder="Message client..."
>

<button
    class="btn primary"
>
    Send
</button>

</form>

{% else %}

<div class="notice">
    Chat is locked until the request is accepted.
</div>

{% endif %}

</div>

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
    Publish Finding
</h2>


{% if r.status in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

<form
    class="form"
    method="post"
    action="{{ url_for('admin_finding',rid=r.id) }}"
>

<input
    type="hidden"
    name="csrf"
    value="{{ csrf }}"
>


<div class="row">

<div class="field">

<label>
    Title
</label>

<input
    name="title"
    required
    maxlength="200"
>

</div>


<div class="field">

<label>
    Severity
</label>

<select name="severity">

<option>INFO</option>
<option>LOW</option>
<option>MEDIUM</option>
<option>HIGH</option>
<option>CRITICAL</option>

</select>

</div>

</div>


<div class="field">

<label>
    Description
</label>

<textarea
    name="description"
    required
></textarea>

</div>


<div class="field">

<label>
    Evidence
</label>

<textarea
    name="evidence"
></textarea>

</div>


<div class="field">

<label>
    Recommendation
</label>

<textarea
    name="recommendation"
></textarea>

</div>


<button
    class="btn primary"
>
    Publish Finding
</button>

</form>

{% else %}

<div class="notice">
    Accept the client before publishing findings.
</div>

{% endif %}

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
    Published Findings
</h2>


{% for f in findings %}

<div class="finding">

<span class="sev sev-{{ f.severity }}">
    {{ f.severity }}
</span>

<h3>
    {{ f.title|e }}
</h3>

<p>
    {{ f.description|e }}
</p>


{% if f.evidence %}

<p>
    <b>Evidence</b>
</p>

<div class="mono">
    {{ f.evidence|e }}
</div>

{% endif %}


{% if f.recommendation %}

<p>
    <b>Recommendation:</b>
    {{ f.recommendation|e }}
</p>

{% endif %}

<span class="small muted">
    {{ f.created_at }}
</span>

</div>

{% else %}

<div class="empty">
    No findings published.
</div>

{% endfor %}

</div>


<script>

function toast(t){

    const box =
        document.getElementById('toastbox');

    const x =
        document.createElement('div');

    x.className = 'toast';

    x.textContent = t;

    box.appendChild(x);

    setTimeout(
        () => x.remove(),
        5000
    );

}


async function enableNotifications(){

    if(!('Notification' in window)){

        toast(
            'Notifications are not supported'
        );

        return;
    }

    const p =
        await Notification.requestPermission();

    toast(
        p === 'granted'
        ? 'Browser notifications enabled'
        : 'Permission denied'
    );

}


const rid =
    {{ r.id|tojson }};

let lastUpdate =
    {{ r.updated_at|tojson }};

let lastMsg =
    {{ messages[-1].id if messages else 0 }};


async function poll(){

    try{

        const d =
            await fetch(
                '/api/admin/request/' +
                rid +
                '?t=' +
                Date.now(),
                {
                    cache:'no-store'
                }
            )
            .then(x => x.json());


        if(
            d.updated_at !== lastUpdate ||
            d.latest_message_id > lastMsg
        ){

            location.reload();

        }

    }
    catch(e){

    }

}


{% if r.status in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

document
    .getElementById('chatForm')
    .addEventListener(
        'submit',
        async function(e){

            e.preventDefault();

            const input =
                document.getElementById(
                    'chatInput'
                );

            const message =
                input.value.trim();

            if(!message){
                return;
            }

            const fd =
                new FormData();

            fd.append(
                'csrf',
                {{ csrf|tojson }}
            );

            fd.append(
                'message',
                message
            );


            const res =
                await fetch(
                    '{{ url_for("admin_message",rid=r.id) }}',
                    {
                        method:'POST',
                        body:fd
                    }
                );


            if(res.ok){

                input.value = '';

                location.reload();

            }
            else{

                toast(
                    'Message failed'
                );

            }

        }
    );

{% endif %}


setInterval(
    poll,
    2500
);

</script>
'''


# ============================================================
# CLIENT STATUS
# ============================================================

CLIENT_STATUS = r'''
<div class="actions">

<a
    class="btn"
    href="{{ url_for('home') }}"
>
    ← Home
</a>

<button
    class="btn"
    onclick="enableNotifications()"
>
    🔔 Enable Notifications
</button>

<a
    class="btn"
    href="{{ report_link }}"
>
    Full Report
</a>

</div>


<div class="card">

<span class="pill">
    REQUEST #{{ r.id }}
</span>

<h1>
    {{ r.web_name|e }}
</h1>

<p class="muted">
    {{ r.target|e }}
</p>

<span
    id="status"
    class="status
    {{ r.status|lower|replace(' ','-') }}"
>
    {{ r.status }}
</span>


<div
    class="grid"
    style="margin-top:18px"
>

<div>

<b>
    Client
</b>

<br>

{{ r.name|e }}

<br>

<span class="muted">
    {{ r.email|e }}
</span>

</div>


<div>

<b>
    Scope
</b>

<br>

{{ r.scope|e }}

</div>

</div>

</div>


<div
    class="grid"
    style="margin-top:18px"
>


<div class="card">

<h2>
    Secure Chat
</h2>


<div
    id="chat"
    class="chat"
>

{% for m in messages %}

<div
    class="msg {{ m.sender|lower }}"
>

<b>
    {{ m.sender }}
</b>

<div>
    {{ m.message|e }}
</div>

<span class="small muted">
    {{ m.created_at }}
</span>

</div>

{% else %}

<div class="empty">
    No messages yet.
</div>

{% endfor %}

</div>


{% if r.status in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

<form
    id="chatForm"
    class="actions"
>

<input
    id="chatInput"
    style="
        flex:1;
        min-width:200px;
        background:#070b15;
        border:1px solid var(--line);
        border-radius:12px;
        color:var(--text);
        padding:12px
    "
    maxlength="4000"
    placeholder="Message administrator..."
>

<button
    class="btn primary"
>
    Send
</button>

</form>

{% else %}

<div class="notice">

{{

'Chat opens after admin approval.'

if r.status == 'PENDING'

else

'Chat is locked because this request was declined.'

}}

</div>

{% endif %}

</div>


<div class="card">

<h2>
    Assessment
</h2>

<p>
    Your request is currently
    <b>{{ r.status }}</b>.
</p>

<p class="muted">
    You will receive a notification when the
    administrator changes the request or publishes
    a finding.
</p>


<div class="grid">

<div>

<b>
    Created
</b>

<br>

{{ r.created_at }}

</div>


<div>

<b>
    Updated
</b>

<br>

<span id="updated">
    {{ r.updated_at }}
</span>

</div>

</div>

</div>

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
    Published Findings
</h2>


{% for f in findings %}

<div class="finding">

<span class="sev sev-{{ f.severity }}">
    {{ f.severity }}
</span>

<h3>
    {{ f.title|e }}
</h3>

<p>
    {{ f.description|e }}
</p>


{% if f.evidence %}

<p>
    <b>Evidence</b>
</p>

<div class="mono">
    {{ f.evidence|e }}
</div>

{% endif %}


{% if f.recommendation %}

<p>
    <b>Recommendation:</b>
    {{ f.recommendation|e }}
</p>

{% endif %}

</div>

{% else %}

<div class="empty">
    No findings have been published yet.
</div>

{% endfor %}

</div>


<script>

const rid =
    {{ r.id|tojson }};

const token =
    {{ token|tojson }};

let lastUpdate =
    {{ r.updated_at|tojson }};

let lastNotif =
    Number(
        localStorage.getItem(
            'matia_client_notif_' + rid
        ) || 0
    );


function toast(t){

    const box =
        document.getElementById(
            'toastbox'
        );

    const x =
        document.createElement(
            'div'
        );

    x.className = 'toast';

    x.textContent = t;

    box.appendChild(x);

    setTimeout(
        () => x.remove(),
        5000
    );

}


async function enableNotifications(){

    if(
        !('Notification' in window)
    ){

        toast(
            'Notifications are not supported'
        );

        return;
    }

    const p =
        await Notification.requestPermission();

    toast(
        p === 'granted'
        ? 'Browser notifications enabled'
        : 'Permission denied'
    );

}


function notify(n){

    toast(
        n.title +
        ': ' +
        n.body
    );


    if(
        'Notification' in window &&
        Notification.permission === 'granted'
    ){

        new Notification(
            n.title,
            {
                body:n.body,
                tag:'matia-client-' + n.id
            }
        );

    }

}


async function poll(){

    try{

        const d =
            await fetch(
                '/api/client/' +
                rid +
                '?token=' +
                encodeURIComponent(token) +
                '&t=' +
                Date.now(),
                {
                    cache:'no-store'
                }
            )
            .then(x => x.json());


        if(
            d.updated_at !== lastUpdate
        ){

            location.reload();

            return;
        }


        const n =
            await fetch(
                '/api/client/' +
                rid +
                '/notifications?token=' +
                encodeURIComponent(token) +
                '&since=' +
                lastNotif +
                '&t=' +
                Date.now(),
                {
                    cache:'no-store'
                }
            )
            .then(x => x.json());


        for(
            const item of n.notifications
        ){

            if(item.id > lastNotif){

                notify(item);

                lastNotif =
                    item.id;

                localStorage.setItem(
                    'matia_client_notif_' + rid,
                    String(lastNotif)
                );

            }

        }

    }
    catch(e){

    }

}


{% if r.status in ['ACCEPTED','IN PROGRESS','COMPLETED'] %}

document
    .getElementById('chatForm')
    .addEventListener(
        'submit',
        async function(e){

            e.preventDefault();

            const input =
                document.getElementById(
                    'chatInput'
                );

            const message =
                input.value.trim();

            if(!message){
                return;
            }


            const fd =
                new FormData();

            fd.append(
                'token',
                token
            );

            fd.append(
                'message',
                message
            );


            const res =
                await fetch(
                    '/status/' +
                    rid +
                    '/message',
                    {
                        method:'POST',
                        body:fd
                    }
                );


            if(res.ok){

                input.value = '';

                location.reload();

            }
            else{

                toast(
                    'Message failed'
                );

            }

        }
    );

{% endif %}


setInterval(
    poll,
    2500
);

poll();

</script>
'''


# ============================================================
# REPORT
# ============================================================

REPORT = r'''
<div class="actions">

<a
    class="btn"
    href="{{ back_url }}"
>
    ← Back
</a>

<button
    class="btn"
    onclick="window.print()"
>
    Print Report
</button>

</div>


<div class="card">

<span class="pill">
    SECURITY ASSESSMENT REPORT
</span>

<h1>
    {{ r.web_name|e }}
</h1>

<p>
    <b>Target:</b>
    {{ r.target|e }}
</p>

<p>
    <b>Client:</b>
    {{ r.name|e }}
    ·
    {{ r.email|e }}
</p>

<p>
    <b>Status:</b>
    {{ r.status }}
</p>

<p>
    <b>Authorized Scope:</b>
    <br>
    {{ r.scope|e }}
</p>

<p class="small muted">
    Request #{{ r.id }}
    ·
    Updated {{ r.updated_at }}
</p>

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
    Findings
</h2>


{% for f in findings %}

<div class="finding">

<span class="sev sev-{{ f.severity }}">
    {{ f.severity }}
</span>

<h3>
    {{ f.title|e }}
</h3>

<p>
    {{ f.description|e }}
</p>


{% if f.evidence %}

<p>
    <b>Evidence</b>
</p>

<div class="mono">
    {{ f.evidence|e }}
</div>

{% endif %}


{% if f.recommendation %}

<p>
    <b>Recommendation</b>
    <br>
    {{ f.recommendation|e }}
</p>

{% endif %}

</div>

{% else %}

<div class="empty">
    No published findings.
</div>

{% endfor %}

</div>
'''


# ============================================================
# DATABASE
# ============================================================

def now():
    return datetime.now(
        timezone.utc
    ).isoformat(
        timespec="seconds"
    )


def db():

    con = sqlite3.connect(
        DB_PATH,
        timeout=15
    )

    con.row_factory = sqlite3.Row

    con.execute(
        "PRAGMA foreign_keys=ON"
    )

    return con


def init_db():

    con = db()

    con.executescript(
        '''
        CREATE TABLE IF NOT EXISTS requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_token TEXT,
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
            request_id INTEGER NOT NULL,
            audience TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );
        '''
    )

    cols = {
        r[1]
        for r in con.execute(
            "PRAGMA table_info(requests)"
        ).fetchall()
    }

    if "client_token" not in cols:

        con.execute(
            "ALTER TABLE requests ADD COLUMN client_token TEXT"
        )

    if "web_name" not in cols:

        con.execute(
            "ALTER TABLE requests ADD COLUMN web_name TEXT DEFAULT 'Website'"
        )

    if "client_ip" not in cols:

        con.execute(
            "ALTER TABLE requests ADD COLUMN client_ip TEXT DEFAULT ''"
        )

    rows = con.execute(
        """
        SELECT id
        FROM requests
        WHERE client_token IS NULL
        OR client_token=''
        """
    ).fetchall()

    for r in rows:

        con.execute(
            """
            UPDATE requests
            SET client_token=?
            WHERE id=?
            """,
            (
                secrets.token_urlsafe(32),
                r[0]
            )
        )

    con.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_notifications_audience_id
        ON notifications(audience,id)
        """
    )

    con.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_messages_request_id
        ON messages(request_id,id)
        """
    )

    con.commit()

    con.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def page(title, template, **ctx):

    content = render_template_string(
        template,
        **ctx
    )

    return render_template_string(
        SHELL,
        title=title,
        content=content,
        css=CSS
    )


def csrf():

    if "csrf" not in session:

        session["csrf"] = (
            secrets.token_urlsafe(24)
        )

    return session["csrf"]


def check_csrf():

    token = request.form.get(
        "csrf",
        ""
    )

    if (
        not token
        or not hmac.compare_digest(
            token,
            session.get("csrf", "")
        )
    ):

        abort(403)


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


def get_request(rid):

    con = db()

    r = con.execute(
        "SELECT * FROM requests WHERE id=?",
        (rid,)
    ).fetchone()

    con.close()

    return r


def valid_client(rid, token):

    r = get_request(rid)

    if (
        not r
        or not token
        or not hmac.compare_digest(
            str(r["client_token"]),
            str(token)
        )
    ):

        abort(404)

    return r


def notify(
    con,
    rid,
    audience,
    kind,
    title,
    body
):

    con.execute(
        """
        INSERT INTO notifications(
            request_id,
            audience,
            kind,
            title,
            body,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            rid,
            audience,
            kind,
            title,
            body,
            now()
        )
    )


def add_system(
    con,
    rid,
    body
):

    con.execute(
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
            rid,
            "SYSTEM",
            body,
            now()
        )
    )


def stats(con):

    total = con.execute(
        "SELECT COUNT(*) FROM requests"
    ).fetchone()[0]

    waiting = con.execute(
        """
        SELECT COUNT(*)
        FROM requests
        WHERE status='PENDING'
        """
    ).fetchone()[0]

    active = con.execute(
        """
        SELECT COUNT(*)
        FROM requests
        WHERE status IN (
            'ACCEPTED',
            'IN PROGRESS'
        )
        """
    ).fetchone()[0]

    findings = con.execute(
        "SELECT COUNT(*) FROM findings"
    ).fetchone()[0]

    return {
        "total": total,
        "waiting": waiting,
        "active": active,
        "findings": findings
    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return page(
        "Home",
        HOME
    )


# ============================================================
# NEW REQUEST
# ============================================================

@app.route(
    "/request",
    methods=["GET", "POST"]
)
def new_request():

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

        if (
            not all([
                name,
                email,
                web_name,
                target,
                scope
            ])
            or request.form.get(
                "authorized"
            ) != "yes"
        ):

            flash(
                "Complete every field and confirm authorization."
            )

            return redirect(
                url_for("new_request")
            )

        token = secrets.token_urlsafe(32)
        timestamp = now()

        con = db()

        cur = con.execute(
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
                timestamp,
                timestamp,
                request.headers.get(
                    "X-Forwarded-For",
                    request.remote_addr or ""
                )
            )
        )

        rid = cur.lastrowid

        add_system(
            con,
            rid,
            "Your security request was submitted and is waiting for administrator review."
        )

        notify(
            con,
            rid,
            "admin",
            "NEW_REQUEST",
            "New security request",
            f"{name} submitted request #{rid} for {web_name}."
        )

        con.commit()
        con.close()

        return redirect(
            url_for(
                "client_status",
                rid=rid,
                token=token
            )
        )

    return page(
        "New Request",
        REQUEST_FORM
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

    r = valid_client(
        rid,
        token
    )

    con = db()

    messages = con.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id
        """,
        (rid,)
    ).fetchall()

    findings = con.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (rid,)
    ).fetchall()

    con.close()

    report = url_for(
        "client_report",
        rid=rid,
        token=token
    )

    return page(
        "Client Portal",
        CLIENT_STATUS,
        r=r,
        messages=messages,
        findings=findings,
        token=token,
        report_link=report
    )


# ============================================================
# CLIENT CHAT
# ============================================================

@app.route(
    "/status/<int:rid>/message",
    methods=["POST"]
)
def client_message(rid):

    token = request.form.get(
        "token",
        ""
    )

    r = valid_client(
        rid,
        token
    )

    msg = request.form.get(
        "message",
        ""
    ).strip()

    if r["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):

        abort(403)

    if not msg or len(msg) > 4000:

        abort(400)

    con = db()

    con.execute(
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
            rid,
            "CLIENT",
            msg,
            now()
        )
    )

    con.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            rid
        )
    )

    notify(
        con,
        rid,
        "admin",
        "CLIENT_MESSAGE",
        "New client message",
        f"{r['name']} sent a new message on request #{rid}."
    )

    con.commit()
    con.close()

    return ("", 204)


# ============================================================
# CLIENT API
# ============================================================

@app.route("/api/client/<int:rid>")
def api_client(rid):

    token = request.args.get(
        "token",
        ""
    )

    r = valid_client(
        rid,
        token
    )

    con = db()

    last = con.execute(
        """
        SELECT id
        FROM messages
        WHERE request_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (rid,)
    ).fetchone()

    con.close()

    return jsonify(
        status=r["status"],
        updated_at=r["updated_at"],
        latest_message_id=(
            last[0]
            if last
            else 0
        )
    )


# ============================================================
# CLIENT NOTIFICATIONS API
# ============================================================

@app.route(
    "/api/client/<int:rid>/notifications"
)
def api_client_notifications(rid):

    token = request.args.get(
        "token",
        ""
    )

    valid_client(
        rid,
        token
    )

    try:
        since = int(
            request.args.get(
                "since",
                0
            )
        )
    except ValueError:
        since = 0

    con = db()

    rows = con.execute(
        """
        SELECT *
        FROM notifications
        WHERE request_id=?
        AND audience='client'
        AND id>?
        ORDER BY id
        LIMIT 50
        """,
        (
            rid,
            since
        )
    ).fetchall()

    latest = con.execute(
        """
        SELECT COALESCE(
            MAX(id),
            0
        )
        FROM notifications
        WHERE request_id=?
        AND audience='client'
        """,
        (rid,)
    ).fetchone()[0]

    con.close()

    return jsonify(
        latest_id=latest,
        notifications=[
            dict(x)
            for x in rows
        ]
    )


# ============================================================
# CLIENT REPORT
# ============================================================

@app.route("/report/<int:rid>")
def client_report(rid):

    token = request.args.get(
        "token",
        ""
    )

    r = valid_client(
        rid,
        token
    )

    con = db()

    findings = con.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (rid,)
    ).fetchall()

    con.close()

    return page(
        "Security Report",
        REPORT,
        r=r,
        findings=findings,
        back_url=url_for(
            "client_status",
            rid=rid,
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

    if session.get("admin"):

        return redirect(
            url_for("admin_dashboard")
        )

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
            hmac.compare_digest(
                email,
                ADMIN_EMAIL
            )
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
                request.args.get(
                    "next"
                )
                or url_for(
                    "admin_dashboard"
                )
            )

        flash(
            "Invalid administrator credentials."
        )

    return page(
        "Admin Login",
        LOGIN,
        admin_email=ADMIN_EMAIL
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    con = db()

    rows = con.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    st = stats(con)

    con.close()

    return page(
        "Admin Console",
        ADMIN_DASH,
        rows=rows,
        stats=st
    )


# ============================================================
# ADMIN DASHBOARD API
# ============================================================

@app.route("/api/admin/dashboard")
@admin_required
def api_admin_dashboard():

    con = db()

    st = stats(con)

    latest = con.execute(
        """
        SELECT COALESCE(
            MAX(id),
            0
        )
        FROM notifications
        WHERE audience='admin'
        """
    ).fetchone()[0]

    latest_update = con.execute(
        """
        SELECT COALESCE(
            MAX(updated_at),
            ''
        )
        FROM requests
        """
    ).fetchone()[0]

    con.close()

    return jsonify(
        stats=st,
        latest_notification_id=latest,
        latest_updated_at=latest_update
    )


# ============================================================
# ADMIN NOTIFICATIONS
# ============================================================

@app.route("/api/admin/notifications")
@admin_required
def api_admin_notifications():

    try:
        since = int(
            request.args.get(
                "since",
                0
            )
        )
    except ValueError:
        since = 0

    con = db()

    rows = con.execute(
        """
        SELECT *
        FROM notifications
        WHERE audience='admin'
        AND id>?
        ORDER BY id
        LIMIT 50
        """,
        (since,)
    ).fetchall()

    con.close()

    return jsonify(
        notifications=[
            dict(x)
            for x in rows
        ]
    )


# ============================================================
# ADMIN CLIENT DETAIL
# ============================================================

@app.route(
    "/admin/request/<int:rid>"
)
@admin_required
def admin_request(rid):

    r = get_request(rid)

    if not r:
        abort(404)

    con = db()

    messages = con.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id=?
        ORDER BY id
        """,
        (rid,)
    ).fetchall()

    findings = con.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (rid,)
    ).fetchall()

    con.close()

    client_link = url_for(
        "client_status",
        rid=rid,
        token=r["client_token"],
        _external=True
    )

    return page(
        "Client #" + str(rid),
        ADMIN_DETAIL,
        r=r,
        messages=messages,
        findings=findings,
        csrf=csrf(),
        client_link=client_link
    )


# ============================================================
# ADMIN CLIENT API
# ============================================================

@app.route(
    "/api/admin/request/<int:rid>"
)
@admin_required
def api_admin_request(rid):

    r = get_request(rid)

    if not r:
        abort(404)

    con = db()

    last = con.execute(
        """
        SELECT id
        FROM messages
        WHERE request_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (rid,)
    ).fetchone()

    con.close()

    return jsonify(
        status=r["status"],
        updated_at=r["updated_at"],
        latest_message_id=(
            last[0]
            if last
            else 0
        )
    )


# ============================================================
# ADMIN STATUS ACTIONS
# ============================================================

@app.route(
    "/admin/request/<int:rid>/decision",
    methods=["POST"]
)
@admin_required
def admin_decision(rid):

    check_csrf()

    action = request.form.get(
        "action",
        ""
    )

    r = get_request(rid)

    if not r:
        abort(404)

    transitions = {

        "ACCEPT": (
            "PENDING",
            "ACCEPTED",
            "Your security request has been ACCEPTED. Secure chat is now open."
        ),

        "DECLINE": (
            "PENDING",
            "DECLINED",
            "Your security request has been DECLINED. The administrator has closed this request."
        ),

        "START": (
            "ACCEPTED",
            "IN PROGRESS",
            "Your security assessment has STARTED. The request is now in progress."
        ),

        "COMPLETE": (
            "IN PROGRESS",
            "COMPLETED",
            "Your security assessment has been marked COMPLETED."
        ),

        "REOPEN": (
            "DECLINED",
            "PENDING",
            "Your security request has been REOPENED and is waiting for administrator review."
        )
    }

    if (
        action not in transitions
        or r["status"]
        != transitions[action][0]
    ):

        flash(
            "That action is not available for the current status."
        )

        return redirect(
            url_for(
                "admin_request",
                rid=rid
            )
        )

    _, new_status, body = (
        transitions[action]
    )

    con = db()

    timestamp = now()

    con.execute(
        """
        UPDATE requests
        SET status=?,
            updated_at=?
        WHERE id=?
        """,
        (
            new_status,
            timestamp,
            rid
        )
    )

    add_system(
        con,
        rid,
        body
    )

    notify(
        con,
        rid,
        "client",
        "STATUS_CHANGE",
        "Security request updated",
        body
    )

    con.commit()
    con.close()

    return redirect(
        url_for(
            "admin_request",
            rid=rid
        )
    )


# ============================================================
# ADMIN CHAT
# ============================================================

@app.route(
    "/admin/request/<int:rid>/message",
    methods=["POST"]
)
@admin_required
def admin_message(rid):

    check_csrf()

    r = get_request(rid)

    msg = request.form.get(
        "message",
        ""
    ).strip()

    if (
        not r
        or not msg
        or len(msg) > 4000
    ):

        abort(400)

    if r["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):

        abort(403)

    con = db()

    con.execute(
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
            rid,
            "ADMIN",
            msg,
            now()
        )
    )

    con.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            rid
        )
    )

    notify(
        con,
        rid,
        "client",
        "ADMIN_MESSAGE",
        "New administrator message",
        "The administrator sent you a new message."
    )

    con.commit()
    con.close()

    return ("", 204)


# ============================================================
# ADMIN FINDINGS
# ============================================================

@app.route(
    "/admin/request/<int:rid>/finding",
    methods=["POST"]
)
@admin_required
def admin_finding(rid):

    check_csrf()

    r = get_request(rid)

    if not r:
        abort(404)

    if r["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):

        abort(403)

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
        not title
        or not description
        or severity not in (
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        )
    ):

        abort(400)

    con = db()

    con.execute(
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
            rid,
            title,
            severity,
            description,
            evidence,
            recommendation,
            now()
        )
    )

    con.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            rid
        )
    )

    notify(
        con,
        rid,
        "client",
        "NEW_FINDING",
        "New security finding published",
        f"A {severity} finding was published for {r['web_name']}."
    )

    con.commit()
    con.close()

    return redirect(
        url_for(
            "admin_request",
            rid=rid
        )
    )


# ============================================================
# ADMIN REPORT
# ============================================================

@app.route(
    "/admin/report/<int:rid>"
)
@admin_required
def admin_report(rid):

    r = get_request(rid)

    if not r:
        abort(404)

    con = db()

    findings = con.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id=?
        ORDER BY id DESC
        """,
        (rid,)
    ).fetchall()

    con.close()

    return page(
        "Security Report",
        REPORT,
        r=r,
        findings=findings,
        back_url=url_for(
            "admin_request",
            rid=rid
        )
    )


# ============================================================
# ERROR PAGES
# ============================================================

@app.errorhandler(403)
def forbidden(e):

    return (
        page(
            "403",
            r'''
            <div class="card">
                <h1>403 · Forbidden</h1>
                <p class="muted">
                    You are not authorized to access
                    this resource.
                </p>
            </div>
            '''
        ),
        403
    )


@app.errorhandler(404)
def not_found(e):

    return (
        page(
            "404",
            r'''
            <div class="card">
                <h1>404 · Not Found</h1>
                <p class="muted">
                    The requested resource does not exist.
                </p>
            </div>
            '''
        ),
        404
    )


# ============================================================
# LOCAL START
# ============================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "10000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
