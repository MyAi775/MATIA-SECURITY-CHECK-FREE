import os
import re
import hmac
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
from markupsafe import escape


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "MATIA_DB_PATH",
    os.path.join(BASE_DIR, "matia_security.db"),
)

app = Flask(__name__)

app.secret_key = os.environ.get(
    "MATIA_SECRET_KEY",
    "CHANGE_ME",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "true").lower() == "true"
    ),
    MAX_CONTENT_LENGTH=1024 * 1024,
)


OWNER_EMAIL = os.environ.get("MATIA_OWNER_EMAIL", "")
OWNER_PASSWORD = os.environ.get("MATIA_OWNER_PASSWORD", "")

ADMIN_EMAIL = os.environ.get("MATIA_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")


STATUSES = (
    "PENDING",
    "ACCEPTED",
    "DECLINED",
    "IN PROGRESS",
    "COMPLETED",
)

SEVERITIES = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()

    conn.executescript(
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
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            recommendation TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id)
                REFERENCES requests(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
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
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(requests)"
        ).fetchall()
    }

    migrations = {
        "client_token":
            "ALTER TABLE requests ADD COLUMN client_token TEXT",
        "web_name":
            "ALTER TABLE requests ADD COLUMN web_name TEXT",
        "client_ip":
            "ALTER TABLE requests ADD COLUMN client_ip TEXT",
    }

    for name, sql in migrations.items():
        if name not in columns:
            conn.execute(sql)

    rows = conn.execute(
        """
        SELECT id
        FROM requests
        WHERE client_token IS NULL
           OR client_token = ''
        """
    ).fetchall()

    for row in rows:
        conn.execute(
            """
            UPDATE requests
            SET client_token=?
            WHERE id=?
            """,
            (
                secrets.token_urlsafe(32),
                row[0],
            ),
        )

    conn.commit()
    conn.close()


init_db()


def valid_target(value):
    return bool(
        re.match(
            r"^https?://[^\s]+$",
            value or "",
            re.I,
        )
    )


def notify(request_id, audience, kind, title, body):
    conn = db()

    conn.execute(
        """
        INSERT INTO notifications(
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

    conn.commit()
    conn.close()


def system_message(request_id, body):
    conn = db()

    conn.execute(
        """
        INSERT INTO messages(
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
            body,
            now(),
        ),
    )

    conn.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            request_id,
        ),
    )

    conn.commit()
    conn.close()


def audit_action(
    request_id,
    actor,
    body,
    notify_client=True,
):
    conn = db()

    conn.execute(
        """
        INSERT INTO messages(
            request_id,
            sender,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            request_id,
            actor,
            body,
            now(),
        ),
    )

    conn.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            request_id,
        ),
    )

    conn.commit()
    conn.close()

    if notify_client:
        notify(
            request_id,
            "CLIENT",
            "chat",
            actor,
            body,
        )


def get_request(request_id):
    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id=?
        """,
        (request_id,),
    ).fetchone()

    conn.close()

    return row


def get_request_by_token(token):
    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE client_token=?
        """,
        (token,),
    ).fetchone()

    conn.close()

    return row


def stats():
    conn = db()

    result = {
        "total": conn.execute(
            "SELECT COUNT(*) FROM requests"
        ).fetchone()[0],

        "waiting": conn.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status='PENDING'
            """
        ).fetchone()[0],

        "active": conn.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status IN (
                'ACCEPTED',
                'IN PROGRESS'
            )
            """
        ).fetchone()[0],

        "completed": conn.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status='COMPLETED'
            """
        ).fetchone()[0],

        "findings": conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0],
    }

    conn.close()

    return result


def safe_int(value):
    try:
        return int(value)
    except Exception:
        return None


def current_role():
    return session.get("role")


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                if roles == ("owner",):
                    target = url_for("owner_login")
                else:
                    target = url_for(
                        "admin_login",
                        next=request.path,
                    )

                return redirect(target)

            return fn(*args, **kwargs)

        return wrapper

    return deco


def staff_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") not in (
            "owner",
            "admin",
        ):
            return redirect(
                url_for(
                    "admin_login",
                    next=request.path,
                )
            )

        return fn(*args, **kwargs)

    return wrapper


@app.after_request
def headers(response):
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
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )

    if request.is_secure:
        response.headers[
            "Strict-Transport-Security"
        ] = (
            "max-age=31536000; "
            "includeSubDomains"
        )

    return response


@app.route("/")
def home():
    return render_template_string(
        PAGE,
        title="MATIA // SECURITY CHECK",
        content=HOME_CONTENT,
    )


@app.route("/how-it-works")
def how_it_works():
    return render_template_string(
        PAGE,
        title="How It Works",
        content=HOW_CONTENT,
    )


@app.route(
    "/request",
    methods=["GET", "POST"],
)
def create_request():

    if request.method == "GET":
        return render_template_string(
            PAGE,
            title="New Security Request",
            content=REQUEST_FORM,
        )

    name = request.form.get(
        "name",
        "",
    ).strip()

    email = request.form.get(
        "email",
        "",
    ).strip()

    web_name = request.form.get(
        "web_name",
        "",
    ).strip()

    target = request.form.get(
        "target",
        "",
    ).strip()

    scope = request.form.get(
        "scope",
        "",
    ).strip()

    authorized = (
        request.form.get(
            "authorized"
        )
        == "yes"
    )

    if not all(
        [
            name,
            email,
            web_name,
            target,
            scope,
        ]
    ) or not authorized:

        message = (
            "Complete every field "
            "and confirm authorization."
        )

        content = (
            '<div class="card">'
            '<h1>Request Error</h1>'
            f'<p class="muted">{escape(message)}</p>'
            '<a class="btn" href="/request">'
            "Back"
            "</a>"
            "</div>"
        )

        return (
            render_template_string(
                PAGE,
                title="Request Error",
                content=content,
            ),
            400,
        )

    if not valid_target(target):

        message = (
            "Target must start with "
            "http:// or https://."
        )

        content = (
            '<div class="card">'
            '<h1>Request Error</h1>'
            f'<p class="muted">{escape(message)}</p>'
            '<a class="btn" href="/request">'
            "Back"
            "</a>"
            "</div>"
        )

        return (
            render_template_string(
                PAGE,
                title="Request Error",
                content=content,
            ),
            400,
        )

    token = secrets.token_urlsafe(32)
    timestamp = now()

    conn = db()

    cur = conn.execute(
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
            request.headers.get(
                "CF-Connecting-IP"
            ) or request.remote_addr,
        ),
    )

    request_id = cur.lastrowid

    conn.commit()
    conn.close()

    notify(
        request_id,
        "STAFF",
        "new_request",
        "New security request",
        f"{name} submitted {web_name}.",
    )

    system_message(
        request_id,
        (
            "Your request has been received "
            "and is waiting for staff review."
        ),
    )

    return redirect(
        url_for(
            "client_status",
            request_id=request_id,
            token=token,
        )
    )


@app.route(
    "/status/<int:request_id>"
)
def client_status(request_id):

    token = request.args.get(
        "token",
        "",
    )

    row = get_request_by_token(token)

    if not row or row["id"] != request_id:
        abort(404)

    return render_template_string(
        PAGE,
        title=f"Client #{request_id}",
        content=CLIENT_STATUS_CONTENT,
        row=dict(row),
    )


@app.route(
    "/api/client/<int:request_id>/data"
)
def client_data(request_id):

    token = request.args.get(
        "token",
        "",
    )

    row = get_request_by_token(token)

    if not row or row["id"] != request_id:
        return jsonify(
            {
                "error": "unauthorized"
            }
        ), 404

    conn = db()

    messages = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,),
        ).fetchall()
    ]

    findings = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (request_id,),
        ).fetchall()
    ]

    notifications = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM notifications
            WHERE request_id=?
              AND audience='CLIENT'
            ORDER BY id DESC
            LIMIT 30
            """,
            (request_id,),
        ).fetchall()
    ]

    conn.close()

    return jsonify(
        {
            "request": dict(row),
            "messages": messages,
            "findings": findings,
            "notifications": notifications,
        }
    )


@app.post(
    "/api/client/<int:request_id>/message"
)
def client_message(request_id):

    token = request.args.get(
        "token",
        "",
    )

    row = get_request_by_token(token)

    if not row or row["id"] != request_id:
        return jsonify(
            {
                "error": "unauthorized"
            }
        ), 404

    if row["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED",
    ):
        return jsonify(
            {
                "error": "chat_locked"
            }
        ), 403

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    message = str(
        data.get(
            "message",
            "",
        )
    ).strip()

    if (
        not message
        or len(message) > 4000
    ):
        return jsonify(
            {
                "error":
                    "invalid_message"
            }
        ), 400

    audit_action(
        request_id,
        "CLIENT",
        message,
        notify_client=False,
    )

    notify(
        request_id,
        "STAFF",
        "chat",
        "Client message",
        message,
    )

    return jsonify(
        {
            "ok": True
        }
    )


@app.route(
    "/report/<int:request_id>"
)
def client_report(request_id):

    token = request.args.get(
        "token",
        "",
    )

    row = get_request_by_token(token)

    if not row or row["id"] != request_id:
        abort(404)

    conn = db()

    findings = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (request_id,),
        ).fetchall()
    ]

    conn.close()

    return render_template_string(
        PAGE,
        title=f"Report #{request_id}",
        content=REPORT_CONTENT,
        row=dict(row),
        findings=findings,
    )


@app.route(
    "/admin/login",
    methods=["GET", "POST"],
)
def admin_login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        )

        password = request.form.get(
            "password",
            "",
        )

        if (
            ADMIN_EMAIL
            and ADMIN_PASSWORD
            and hmac.compare_digest(
                email,
                ADMIN_EMAIL,
            )
            and hmac.compare_digest(
                password,
                ADMIN_PASSWORD,
            )
        ):
            session.clear()

            session["role"] = "admin"
            session["email"] = ADMIN_EMAIL

            return redirect(
                request.args.get(
                    "next"
                )
                or url_for(
                    "admin_panel"
                )
            )

        return (
            render_template_string(
                PAGE,
                title="Admin Login",
                content=LOGIN_CONTENT,
                kind="Admin",
                error=(
                    "Invalid admin credentials."
                ),
            ),
            401,
        )

    return render_template_string(
        PAGE,
        title="Admin Login",
        content=LOGIN_CONTENT,
        kind="Admin",
        error="",
    )


@app.route(
    "/owner/login",
    methods=["GET", "POST"],
)
def owner_login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            "",
        )

        password = request.form.get(
            "password",
            "",
        )

        if (
            OWNER_EMAIL
            and OWNER_PASSWORD
            and hmac.compare_digest(
                email,
                OWNER_EMAIL,
            )
            and hmac.compare_digest(
                password,
                OWNER_PASSWORD,
            )
        ):
            session.clear()

            session["role"] = "owner"
            session["email"] = OWNER_EMAIL

            return redirect(
                request.args.get(
                    "next"
                )
                or url_for(
                    "owner_panel"
                )
            )

        return (
            render_template_string(
                PAGE,
                title="Owner Login",
                content=LOGIN_CONTENT,
                kind="Owner",
                error=(
                    "Invalid owner credentials."
                ),
            ),
            401,
        )

    return render_template_string(
        PAGE,
        title="Owner Login",
        content=LOGIN_CONTENT,
        kind="Owner",
        error="",
    )


@app.get("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


def list_clients(
    filter_status=None,
    q=None,
):
    conn = db()

    sql = "SELECT * FROM requests"
    params = []
    where = []

    if filter_status:
        where.append(
            "status=?"
        )
        params.append(
            filter_status
        )

    if q:
        where.append(
            """
            (
                name LIKE ?
                OR email LIKE ?
                OR web_name LIKE ?
                OR target LIKE ?
            )
            """
        )

        like = f"%{q}%"

        params.extend(
            [
                like,
                like,
                like,
                like,
            ]
        )

    if where:
        sql += (
            " WHERE "
            + " AND ".join(where)
        )

    sql += " ORDER BY id DESC"

    rows = [
        dict(r)
        for r in conn.execute(
            sql,
            params,
        ).fetchall()
    ]

    conn.close()

    return rows


def panel_html(
    kind,
    include_terminal=False,
):
    return render_template_string(
        PANEL_PAGE,
        title=f"{kind} Panel",
        role=kind.lower(),
        stats=stats(),
        clients=list_clients(
            q=request.args.get(
                "q",
                "",
            ).strip()
        ),
        include_terminal=include_terminal,
    )


@app.get("/admin")
@role_required(
    "admin",
    "owner",
)
def admin_panel():

    return panel_html(
        "Admin",
        include_terminal=False,
    )


@app.get("/owner")
@role_required("owner")
def owner_panel():

    return panel_html(
        "Owner",
        include_terminal=True,
    )


@app.get(
    "/admin/client/<int:request_id>"
)
@staff_required
def staff_client_detail(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    conn = db()

    messages = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,),
        ).fetchall()
    ]

    findings = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (request_id,),
        ).fetchall()
    ]

    conn.close()

    return render_template_string(
        STAFF_DETAIL,
        row=dict(row),
        messages=messages,
        findings=findings,
        role=current_role(),
    )


@app.post(
    "/staff/client/<int:request_id>/status"
)
@staff_required
def change_status(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    action = request.form.get(
        "action",
        "",
    )

    transitions = {
        "accept": (
            "PENDING",
            "ACCEPTED",
            (
                "Your security request has "
                "been ACCEPTED. Secure chat "
                "is now open."
            ),
        ),

        "decline": (
            (
                "PENDING",
                "ACCEPTED",
                "IN PROGRESS",
            ),
            "DECLINED",
            (
                "Your security request has "
                "been DECLINED. The administrator "
                "has closed this request."
            ),
        ),

        "reopen": (
            "DECLINED",
            "PENDING",
            (
                "Your security request has "
                "been REOPENED and returned "
                "to review."
            ),
        ),

        "start": (
            "ACCEPTED",
            "IN PROGRESS",
            (
                "Your assessment has STARTED. "
                "The security review is now "
                "in progress."
            ),
        ),

        "complete": (
            "IN PROGRESS",
            "COMPLETED",
            (
                "Your assessment has been "
                "MARKED COMPLETED. Your report "
                "is available in the portal."
            ),
        ),
    }

    if action not in transitions:
        abort(400)

    allowed_from, new_status, message = (
        transitions[action]
    )

    if isinstance(
        allowed_from,
        tuple,
    ):
        allowed = (
            row["status"]
            in allowed_from
        )
    else:
        allowed = (
            row["status"]
            == allowed_from
        )

    if not allowed:
        return redirect(
            url_for(
                "staff_client_detail",
                request_id=request_id,
            )
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
            request_id,
        ),
    )

    conn.commit()
    conn.close()

    system_message(
        request_id,
        message,
    )

    notify(
        request_id,
        "CLIENT",
        "status",
        "Security request updated",
        message,
    )

    return redirect(
        url_for(
            "staff_client_detail",
            request_id=request_id,
        )
    )


@app.post(
    "/staff/client/<int:request_id>/message"
)
@staff_required
def staff_message(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    message = request.form.get(
        "message",
        "",
    ).strip()

    if (
        not message
        or len(message) > 4000
    ):
        return redirect(
            url_for(
                "staff_client_detail",
                request_id=request_id,
            )
        )

    actor = (
        "OWNER"
        if current_role() == "owner"
        else "ADMIN"
    )

    audit_action(
        request_id,
        actor,
        message,
        notify_client=True,
    )

    return redirect(
        url_for(
            "staff_client_detail",
            request_id=request_id,
        )
    )


@app.post(
    "/staff/client/<int:request_id>/finding"
)
@staff_required
def add_finding(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    title = request.form.get(
        "title",
        "",
    ).strip()

    severity = request.form.get(
        "severity",
        "INFO",
    ).upper().strip()

    description = request.form.get(
        "description",
        "",
    ).strip()

    evidence = request.form.get(
        "evidence",
        "",
    ).strip()

    recommendation = request.form.get(
        "recommendation",
        "",
    ).strip()

    if (
        not title
        or not description
        or severity not in SEVERITIES
    ):
        return redirect(
            url_for(
                "staff_client_detail",
                request_id=request_id,
            )
        )

    conn = db()

    conn.execute(
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

    conn.execute(
        """
        UPDATE requests
        SET updated_at=?
        WHERE id=?
        """,
        (
            now(),
            request_id,
        ),
    )

    conn.commit()
    conn.close()

    body = (
        f"A new {severity} finding "
        f"was published: {title}"
    )

    system_message(
        request_id,
        body,
    )

    notify(
        request_id,
        "CLIENT",
        "finding",
        "New finding",
        body,
    )

    return redirect(
        url_for(
            "staff_client_detail",
            request_id=request_id,
        )
    )


@app.get(
    "/staff/client/<int:request_id>/report"
)
@staff_required
def staff_report(request_id):

    row = get_request(request_id)

    if not row:
        abort(404)

    conn = db()

    findings = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (request_id,),
        ).fetchall()
    ]

    conn.close()

    return render_template_string(
        STAFF_REPORT,
        row=dict(row),
        findings=findings,
    )


@app.get(
    "/api/staff/notifications"
)
@staff_required
def staff_notifications():

    conn = db()

    rows = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM notifications
            WHERE audience='STAFF'
            ORDER BY id DESC
            LIMIT 30
            """
        ).fetchall()
    ]

    conn.close()

    return jsonify(rows)


@app.get(
    "/api/staff/client/<int:request_id>/data"
)
@staff_required
def staff_client_data(request_id):

    row = get_request(request_id)

    if not row:
        return jsonify(
            {
                "error":
                    "not_found"
            }
        ), 404

    conn = db()

    messages = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id=?
            ORDER BY id ASC
            """,
            (request_id,),
        ).fetchall()
    ]

    findings = [
        dict(r)
        for r in conn.execute(
            """
            SELECT *
            FROM findings
            WHERE request_id=?
            ORDER BY id DESC
            """,
            (request_id,),
        ).fetchall()
    ]

    conn.close()

    return jsonify(
        {
            "request": dict(row),
            "messages": messages,
            "findings": findings,
        }
    )


@app.route(
    "/owner/command",
    methods=["POST"],
)
@role_required("owner")
def owner_command():

    raw = request.form.get(
        "command",
        "",
    ).strip()

    result = execute_command(
        raw,
        "owner",
    )

    return jsonify(
        {
            "ok": result[0],
            "output": result[1],
        }
    )


@app.route(
    "/admin/command",
    methods=["POST"],
)
@role_required(
    "admin",
    "owner",
)
def admin_command():

    raw = request.form.get(
        "command",
        "",
    ).strip()

    result = execute_command(
        raw,
        "admin",
    )

    return jsonify(
        {
            "ok": result[0],
            "output": result[1],
        }
    )


def execute_command(
    raw,
    role,
):

    if not raw:
        return False, "Type /help"

    parts = raw.split()

    cmd = parts[0].lower()

    arg = (
        safe_int(parts[1])
        if len(parts) > 1
        else None
    )

    if cmd == "/help":

        base = [
            "/help",
            "/clients",
            "/pending",
            "/active",
            "/completed",
            "/declined",
            "/stats",
            "/client N",
            "/status N",
            "/findings N",
            "/report N",
            "/accept N",
            "/decline N",
            "/reopen N",
            "/start N",
            "/complete N",
            "/message N TEXT",
            "/announce TEXT",
            "/clear",
        ]

        if role == "owner":
            base += [
                "/search TEXT",
                "/findings-total",
                "/notify N TEXT",
                "/maintenance on|off",
            ]

        return True, "\n".join(base)

    if cmd == "/clear":
        return True, "Terminal cleared."

    if cmd == "/stats":
        return True, json.dumps(
            stats(),
            indent=2,
        )

    if cmd == "/clients":
        rows = list_clients()

    elif cmd == "/pending":
        rows = list_clients(
            "PENDING"
        )

    elif cmd == "/active":

        rows = (
            list_clients(
                "IN PROGRESS"
            )
            + list_clients(
                "ACCEPTED"
            )
        )

    elif cmd == "/completed":

        rows = list_clients(
            "COMPLETED"
        )

    elif cmd == "/declined":

        rows = list_clients(
            "DECLINED"
        )

    elif cmd in (
        "/client",
        "/status",
        "/findings",
        "/report",
    ):

        if arg is None:
            return (
                False,
                f"Usage: {cmd} N",
            )

        row = get_request(arg)

        if not row:
            return False, "Client not found."

        if cmd == "/client":

            return True, json.dumps(
                dict(row),
                indent=2,
            )

        if cmd == "/status":

            return (
                True,
                (
                    f"#{arg} "
                    f"{row['web_name']} "
                    f"→ {row['status']}"
                ),
            )

        conn = db()

        if cmd == "/findings":

            rows2 = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT *
                    FROM findings
                    WHERE request_id=?
                    ORDER BY id DESC
                    """,
                    (arg,),
                ).fetchall()
            ]

            conn.close()

            return (
                True,
                json.dumps(
                    rows2,
                    indent=2,
                ),
            )

        findings = [
            dict(r)
            for r in conn.execute(
                """
                SELECT *
                FROM findings
                WHERE request_id=?
                ORDER BY id DESC
                """,
                (arg,),
            ).fetchall()
        ]

        conn.close()

        return (
            True,
            (
                f"Report for #{arg}: "
                f"{row['web_name']} | "
                f"{row['status']} | "
                f"findings={len(findings)}"
            ),
        )

    elif cmd in (
        "/accept",
        "/decline",
        "/reopen",
        "/start",
        "/complete",
    ):

        if arg is None:
            return (
                False,
                f"Usage: {cmd} N",
            )

        row = get_request(arg)

        if not row:
            return False, "Client not found."

        transition = {
            "/accept": (
                "PENDING",
                "ACCEPTED",
                (
                    "Your security request has "
                    "been ACCEPTED. Secure chat "
                    "is now open."
                ),
            ),

            "/decline": (
                (
                    "PENDING",
                    "ACCEPTED",
                    "IN PROGRESS",
                ),
                "DECLINED",
                (
                    "Your security request has "
                    "been DECLINED. The "
                    "administrator has closed "
                    "this request."
                ),
            ),

            "/reopen": (
                "DECLINED",
                "PENDING",
                (
                    "Your security request has "
                    "been REOPENED and returned "
                    "to review."
                ),
            ),

            "/start": (
                "ACCEPTED",
                "IN PROGRESS",
                (
                    "Your assessment has STARTED. "
                    "The security review is now "
                    "in progress."
                ),
            ),

            "/complete": (
                "IN PROGRESS",
                "COMPLETED",
                (
                    "Your assessment has been "
                    "MARKED COMPLETED. Your "
                    "report is available in "
                    "the portal."
                ),
            ),
        }[cmd]

        old, new, message = transition

        allowed = (
            row["status"] in old
            if isinstance(old, tuple)
            else row["status"] == old
        )

        if not allowed:
            return (
                False,
                (
                    "Invalid transition: "
                    f"{row['status']} -> {new}"
                ),
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
                new,
                now(),
                arg,
            ),
        )

        conn.commit()
        conn.close()

        system_message(
            arg,
            message,
        )

        notify(
            arg,
            "CLIENT",
            "status",
            "Security request updated",
            message,
        )

        return (
            True,
            f"#{arg} -> {new}",
        )

    elif cmd == "/message":

        if (
            arg is None
            or len(parts) < 3
        ):
            return (
                False,
                "Usage: /message N TEXT",
            )

        message = raw.split(
            None,
            2,
        )[2].strip()

        row = get_request(arg)

        if not row:
            return (
                False,
                "Client not found.",
            )

        actor = (
            "OWNER"
            if role == "owner"
            else "ADMIN"
        )

        audit_action(
            arg,
            actor,
            message,
            notify_client=True,
        )

        return (
            True,
            f"Message sent to #{arg}.",
        )

    elif cmd == "/announce":

        text_msg = (
            raw.split(
                None,
                1,
            )[1].strip()
            if len(parts) > 1
            else ""
        )

        if not text_msg:
            return (
                False,
                "Usage: /announce TEXT",
            )

        for row in list_clients():

            system_message(
                row["id"],
                (
                    "STAFF ANNOUNCEMENT: "
                    f"{text_msg}"
                ),
            )

            notify(
                row["id"],
                "CLIENT",
                "announcement",
                "MATIA // SECURITY CHECK",
                text_msg,
            )

        return (
            True,
            "Announcement sent to all clients.",
        )

    elif cmd == "/search":

        if role != "owner":
            return (
                False,
                "Owner-only command.",
            )

        query = (
            raw.split(
                None,
                1,
            )[1].strip()
            if len(parts) > 1
            else ""
        )

        rows = list_clients(
            q=query
        )

    elif cmd == "/findings-total":

        if role != "owner":
            return (
                False,
                "Owner-only command.",
            )

        return (
            True,
            (
                "Total findings: "
                f"{stats()['findings']}"
            ),
        )

    elif cmd == "/notify":

        if role != "owner":
            return (
                False,
                "Owner-only command.",
            )

        if (
            arg is None
            or len(parts) < 3
        ):
            return (
                False,
                "Usage: /notify N TEXT",
            )

        msg = raw.split(
            None,
            2,
        )[2]

        notify(
            arg,
            "CLIENT",
            "owner",
            "Owner notification",
            msg,
        )

        return (
            True,
            f"Notification sent to #{arg}.",
        )

    elif cmd == "/maintenance":

        if role != "owner":
            return (
                False,
                "Owner-only command.",
            )

        mode = (
            parts[1].lower()
            if len(parts) > 1
            else ""
        )

        if mode not in (
            "on",
            "off",
        ):
            return (
                False,
                "Usage: /maintenance on|off",
            )

        session[
            "maintenance_mode"
        ] = mode == "on"

        return (
            True,
            (
                "Maintenance mode: "
                f"{mode.upper()} "
                "(session preview only; "
                "set a global production "
                "flag if you want "
                "maintenance enforcement)."
            ),
        )

    else:
        return (
            False,
            (
                f"Unknown command: {cmd}. "
                "Try /help"
            ),
        )

    lines = [
        (
            f"#{r['id']} | "
            f"{r['status']} | "
            f"{r['name']} | "
            f"{r['web_name']}"
        )
        for r in rows
    ]

    return (
        True,
        (
            "\n".join(lines)
            if lines
            else "No clients found."
        ),
    )


PAGE = r'''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>
<title>{{title}}</title>

<style>
:root{
    --bg:#07090f;
    --panel:#0d111a;
    --panel2:#111827;
    --line:#243047;
    --txt:#f5f7fb;
    --muted:#93a0b7;
    --accent:#7c5cff;
    --good:#29d17d;
    --warn:#f6b73c;
    --bad:#ff5b6e;
}

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at 15% 10%,
            #182047 0,
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 20%,
            #1a1037 0,
            transparent 28%
        ),
        var(--bg);
    color:var(--txt);
    font-family:
        Inter,
        Arial,
        sans-serif;
}

.wrap{
    max-width:1200px;
    margin:auto;
    padding:26px;
}

.nav{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:16px;
    margin-bottom:22px;
}

.brand{
    font-weight:900;
    letter-spacing:1.5px;
}

.links{
    display:flex;
    gap:12px;
    flex-wrap:wrap;
}

.links a,
.btn{
    color:var(--txt);
    text-decoration:none;
    border:1px solid var(--line);
    padding:10px 14px;
    border-radius:12px;
    background:#0d1320;
    cursor:pointer;
}

.btn.primary{
    background:
        linear-gradient(
            135deg,
            #7c5cff,
            #4f8cff
        );
    border:0;
}

.hero{
    padding:38px 0;
}

.hero h1{
    font-size:
        clamp(
            38px,
            8vw,
            72px
        );
    margin:
        0 0 14px;
}

.hero p{
    max-width:760px;
    color:var(--muted);
    font-size:18px;
    line-height:1.7;
}

.grid{
    display:grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                220px,
                1fr
            )
        );
    gap:16px;
}

.card{
    background:
        linear-gradient(
            180deg,
            rgba(17,24,39,.94),
            rgba(10,14,23,.94)
        );
    border:1px solid var(--line);
    border-radius:18px;
    padding:20px;
    box-shadow:
        0 12px 40px
        rgba(0,0,0,.2);
}

.stat{
    font-size:34px;
    font-weight:900;
}

.muted{
    color:var(--muted);
}

.pill{
    display:inline-block;
    padding:6px 9px;
    border-radius:999px;
    font-size:12px;
    font-weight:800;
    background:#20283a;
}

.status-PENDING{
    color:var(--warn);
}

.status-ACCEPTED,
.status-COMPLETED{
    color:var(--good);
}

.status-DECLINED{
    color:var(--bad);
}

.status-IN{
    color:#64b5ff;
}

input,
textarea,
select{
    width:100%;
    background:#080c14;
    color:var(--txt);
    border:1px solid var(--line);
    border-radius:12px;
    padding:12px;
    margin:
        6px 0
        14px;
}

textarea{
    min-height:120px;
    resize:vertical;
}

label{
    font-size:13px;
    color:var(--muted);
}

.split{
    display:grid;
    grid-template-columns:
        1.1fr
        .9fr;
    gap:18px;
}

@media(max-width:850px){
    .split{
        grid-template-columns:1fr;
    }
}

.client{
    display:flex;
    justify-content:space-between;
    gap:14px;
    align-items:center;
    padding:15px;
    border:1px solid var(--line);
    border-radius:14px;
    background:#0a0f18;
    margin:9px 0;
}

.mono{
    font-family:
        ui-monospace,
        monospace;
    white-space:pre-wrap;
}

.msg{
    padding:10px 12px;
    border-left:
        3px solid
        var(--accent);
    background:#0a0f18;
    border-radius:9px;
    margin:8px 0;
}

.finding{
    border:1px solid var(--line);
    padding:15px;
    border-radius:14px;
    margin:10px 0;
}

.sev{
    font-weight:900;
}

.sev.CRITICAL,
.sev.HIGH{
    color:var(--bad);
}

.sev.MEDIUM{
    color:var(--warn);
}

.sev.LOW,
.sev.INFO{
    color:#67b7ff;
}

.term{
    background:#030507;
    border:1px solid #1f2d41;
    border-radius:16px;
    padding:15px;
}

.termout{
    height:340px;
    overflow:auto;
    background:#05070a;
    padding:14px;
    border-radius:12px;
    font-family:
        ui-monospace,
        monospace;
    color:#9effc3;
    white-space:pre-wrap;
}

.mini{
    font-size:12px;
}
</style>
</head>

<body>

<div class="wrap">

<div class="nav">

<div class="brand">
MATIA // SECURITY CHECK
</div>

<div class="links">

<a href="/">
Home
</a>

<a href="/how-it-works">
How It Works
</a>

{% if session.get('role')=='owner' %}
<a href="/owner">
Owner
</a>
{% endif %}

{% if session.get('role') in ['owner','admin'] %}
<a href="/admin">
Admin
</a>

<a href="/logout">
Logout
</a>
{% endif %}

</div>
</div>

{{content|safe}}

</div>

</body>
</html>
'''


HOME_CONTENT = r'''
<section class="hero">

<div class="pill">
AUTHORIZED SECURITY OPERATIONS
</div>

<h1>
Security review,
<br>
with control.
</h1>

<p>
MATIA // SECURITY CHECK is a
request-to-report portal for
authorized web security assessments.
Clients submit scope, staff review
requests, chat during the assessment,
and publish findings into a structured
report.
</p>

<div class="links">

<a
    class="btn primary"
    href="/request"
>
Start a Security Request
</a>

<a
    class="btn"
    href="/how-it-works"
>
How It Works
</a>

</div>

</section>

<div class="grid">

<div class="card">
<h3>
🔐 Authorization first
</h3>

<p class="muted">
Every request records the client,
target and authorized scope before
staff action.
</p>
</div>

<div class="card">
<h3>
💬 Live staff chat
</h3>

<p class="muted">
Accepted clients can exchange
messages with Admin or Owner through
the portal.
</p>
</div>

<div class="card">
<h3>
📝 Evidence-based report
</h3>

<p class="muted">
Published findings include severity,
evidence, description and remediation.
</p>
</div>

</div>
'''


HOW_CONTENT = r'''
<div class="hero">

<div class="pill">
HOW IT WORKS
</div>

<h1>
From request to report.
</h1>

<p class="muted">
A clear lifecycle for authorized
security assessments.
</p>

</div>

<div class="grid">

<div class="card">
<h3>
01 · Submit Request
</h3>

<p class="muted">
Client provides identity, web name,
target and authorized scope, then
confirms permission to request testing.
</p>
</div>

<div class="card">
<h3>
02 · Staff Review
</h3>

<p class="muted">
Admin or Owner opens the request
and decides whether it can proceed.
</p>
</div>

<div class="card">
<h3>
03 · Accept / Decline
</h3>

<p class="muted">
Accept unlocks secure portal chat.
Decline closes the request.
Owner/Admin can reopen it.
</p>
</div>

<div class="card">
<h3>
04 · Live Chat
</h3>

<p class="muted">
Client and staff can communicate
both ways while the assessment is open.
</p>
</div>

<div class="card">
<h3>
05 · Assessment
</h3>

<p class="muted">
Accepted work can move to
IN PROGRESS. Keep testing limited
to authorized scope.
</p>
</div>

<div class="card">
<h3>
06 · Findings
</h3>

<p class="muted">
Staff can publish INFO, LOW, MEDIUM,
HIGH or CRITICAL findings with
evidence and recommendations.
</p>
</div>

<div class="card">
<h3>
07 · Complete
</h3>

<p class="muted">
Mark the assessment completed and
leave the report available to client.
</p>
</div>

<div class="card">
<h3>
08 · Notifications
</h3>

<p class="muted">
The portal polls for new messages,
status changes and findings.
Browser notifications can be shown
when permitted.
</p>
</div>

</div>
'''


REQUEST_FORM = r'''
<div class="card">

<div class="pill">
NEW REQUEST
</div>

<h1>
Request a Security Assessment
</h1>

<form method="post">

<label>
Your Name
</label>

<input
    name="name"
    required
>

<label>
Your Email
</label>

<input
    name="email"
    type="email"
    required
>

<label>
Web Name
</label>

<input
    name="web_name"
    required
>

<label>
Web Target
</label>

<input
    name="target"
    placeholder="https://example.com"
    required
>

<label>
Authorized Scope
</label>

<textarea
    name="scope"
    placeholder="Example: public website only; no accounts; no destructive testing"
    required
></textarea>

<label>

<input
    style="width:auto"
    type="checkbox"
    name="authorized"
    value="yes"
    required
>

I confirm I own this target or have
explicit authorization to request
testing within the scope above.

</label>

<button
    class="btn primary"
    type="submit"
>
Submit Request
</button>

</form>

</div>
'''


CLIENT_STATUS_CONTENT = r'''
<div class="hero">

<div class="pill">
CLIENT PORTAL #{{row.id}}
</div>

<h1>
{{row.web_name}}
</h1>

<p class="muted">
Target: {{row.target}}
· Scope: {{row.scope}}
</p>

</div>

<div class="grid">

<div class="card">

<h3>
Status
</h3>

<div
    id="status"
    class="stat"
>
{{row.status}}
</div>

<div class="muted mini">
Updated: {{row.updated_at}}
</div>

</div>

<div class="card">

<h3>
Report
</h3>

<a
    class="btn"
    href="/report/{{row.id}}?token={{row.client_token}}"
>
Open Full Report
</a>

</div>

</div>

<div
    class="split"
    style="margin-top:18px"
>

<div class="card">

<h3>
Live Chat
</h3>

<div
    id="chat"
    style="max-height:440px;overflow:auto"
>
</div>

<div
    id="chatbox"
    style="display:none"
>

<textarea
    id="msg"
    placeholder="Message staff..."
></textarea>

<button
    class="btn primary"
    onclick="sendMsg()"
>
Send
</button>

</div>

<p
    id="locked"
    class="muted"
></p>

</div>

<div class="card">

<h3>
Published Findings
</h3>

<div id="findings">
</div>

</div>

</div>

<script>
const rid={{row.id}};
const token={{row.client_token|tojson}};

let lastNote=Number(
    localStorage.getItem(
        'matia_last_note_'+rid
    ) || 0
);

async function refresh(){

    const r=await fetch(
        `/api/client/${rid}/data?token=${
            encodeURIComponent(token)
        }`
    );

    if(!r.ok){
        return;
    }

    const d=await r.json();

    document.querySelector(
        '#status'
    ).textContent=d.request.status;

    const open=[
        'ACCEPTED',
        'IN PROGRESS',
        'COMPLETED'
    ].includes(
        d.request.status
    );

    document.querySelector(
        '#locked'
    ).textContent=open
        ? 'Chat is open.'
        : 'Chat opens after staff acceptance.';

    document.querySelector(
        '#chatbox'
    ).style.display=open
        ? 'block'
        : 'none';

    document.querySelector(
        '#chat'
    ).innerHTML=d.messages.map(
        m=>`
        <div class="msg">
            <b>${escapeHtml(m.sender)}</b>
            <div>
                ${escapeHtml(m.message)}
            </div>
            <div class="mini muted">
                ${escapeHtml(m.created_at)}
            </div>
        </div>
        `
    ).join('');

    document.querySelector(
        '#findings'
    ).innerHTML=d.findings.map(
        f=>`
        <div class="finding">

            <div class="sev ${
                escapeHtml(f.severity)
            }">
                ${escapeHtml(f.severity)}
                ·
                ${escapeHtml(f.title)}
            </div>

            <p>
                ${escapeHtml(f.description)}
            </p>

            <div class="mono mini">
                ${escapeHtml(
                    f.evidence || ''
                )}
            </div>

            <p class="muted">
                ${escapeHtml(
                    f.recommendation || ''
                )}
            </p>

        </div>
        `
    ).join('')
    || '<p class="muted">No published findings yet.</p>';

    for(
        const n of d.notifications
            .slice()
            .reverse()
    ){

        if(
            n.id>lastNote
            &&
            'Notification' in window
            &&
            Notification.permission==='granted'
        ){

            new Notification(
                n.title,
                {
                    body:n.body
                }
            );

            lastNote=n.id;

            localStorage.setItem(
                'matia_last_note_'+rid,
                lastNote
            );
        }
    }
}


function escapeHtml(v){

    return String(
        v ?? ''
    ).replace(
        /[&<>'"]/g,
        c=>({
            '&':'&amp;',
            '<':'&lt;',
            '>':'&gt;',
            "'":'&#39;',
            '"':'&quot;'
        }[c])
    );
}


async function sendMsg(){

    const el=document.getElementById(
        'msg'
    );

    const message=el.value.trim();

    if(!message){
        return;
    }

    await fetch(
        `/api/client/${rid}/message?token=${
            encodeURIComponent(token)
        }`,
        {
            method:'POST',
            headers:{
                'Content-Type':
                    'application/json'
            },
            body:JSON.stringify({
                message
            })
        }
    );

    el.value='';

    refresh();
}


if(
    'Notification' in window
    &&
    Notification.permission==='default'
){

    Notification.requestPermission();
}


refresh();

setInterval(
    refresh,
    2500
);
</script>
'''


REPORT_CONTENT = r'''
<div class="hero">

<div class="pill">
SECURITY REPORT #{{row.id}}
</div>

<h1>
{{row.web_name}}
</h1>

<p class="muted">
Target: {{row.target}}
· Final status: {{row.status}}
</p>

</div>

<div class="card">

<p>
<b>Client:</b>
{{row.name}}
·
{{row.email}}
</p>

<p>
<b>Authorized scope:</b>
{{row.scope}}
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

<div class="sev {{f.severity}}">
{{f.severity}}
·
{{f.title}}
</div>

<p>
{{f.description}}
</p>

{% if f.evidence %}

<div class="mono">
{{f.evidence}}
</div>

{% endif %}

{% if f.recommendation %}

<p class="muted">
<b>Recommendation:</b>
{{f.recommendation}}
</p>

{% endif %}

</div>

{% else %}

<p class="muted">
No findings published yet.
</p>

{% endfor %}

</div>
'''


LOGIN_CONTENT = r'''
<div
    class="card"
    style="max-width:520px;margin:60px auto"
>

<div class="pill">
{{kind.upper()}} ACCESS
</div>

<h1>
{{kind}} Login
</h1>

{% if error %}

<p style="color:var(--bad)">
{{error}}
</p>

{% endif %}

<form method="post">

<label>
Email
</label>

<input
    name="email"
    type="email"
    required
>

<label>
Password
</label>

<input
    name="password"
    type="password"
    required
>

<button
    class="btn primary"
>
Enter {{kind}} Panel
</button>

</form>

</div>
'''


PANEL_PAGE = r'''
<div class="hero">

<div class="pill">
{{role.upper()}} CONSOLE
</div>

<h1>
{{role.title()}} Operations.
</h1>

<p class="muted">

{% if role=='owner' %}

Full control, command center
and staff-level operations.

{% else %}

Client control center with request
lifecycle, chat and reporting tools.

{% endif %}

</p>

</div>


<div class="grid">

<div class="card">

<div class="stat">
{{stats.total}}
</div>

<div class="muted">
Total Clients
</div>

</div>


<div class="card">

<div class="stat">
{{stats.waiting}}
</div>

<div class="muted">
Waiting Review
</div>

</div>


<div class="card">

<div class="stat">
{{stats.active}}
</div>

<div class="muted">
Active
</div>

</div>


<div class="card">

<div class="stat">
{{stats.completed}}
</div>

<div class="muted">
Completed
</div>

</div>


<div class="card">

<div class="stat">
{{stats.findings}}
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

<div class="links">

<form method="get">

<input
    style="min-width:260px"
    name="q"
    value="{{request.args.get('q','')}}"
    placeholder="Search people, email, target..."
>

<button class="btn">
Search
</button>

</form>

</div>


<h2>
Client Queue
</h2>


{% for c in clients %}

<div class="client">

<div>

<b>
#{{c.id}}
·
{{c.web_name}}
</b>

<div class="muted">
{{c.name}}
·
{{c.email}}
·
{{c.target}}
</div>

</div>


<div>

<span
    class="
        pill
        status-{{c.status|replace(' ','-')}}
    "
>
{{c.status}}
</span>

<a
    class="btn"
    href="/admin/client/{{c.id}}"
>
Open
</a>

</div>

</div>

{% else %}

<p class="muted">
No clients yet.
</p>

{% endfor %}

</div>


{% if include_terminal %}

<div
    class="term"
    style="margin-top:18px"
>

<h2>
OWNER // COMMAND CENTER
</h2>

<div
    id="out"
    class="termout"
>
Type /help to begin.
</div>

<div
    style="
        display:flex;
        gap:8px;
        margin-top:10px
    "
>

<input
    id="cmd"
    placeholder="/clients"
>

<button
    class="btn primary"
    onclick="runCommand()"
>
EXECUTE
</button>

</div>

</div>

{% endif %}


<script>

{% if include_terminal %}

async function runCommand(){

    const el=document.getElementById(
        'cmd'
    );

    const raw=el.value.trim();

    if(!raw){
        return;
    }

    const r=await fetch(
        '/owner/command',
        {
            method:'POST',
            headers:{
                'Content-Type':
                    'application/x-www-form-urlencoded'
            },
            body:new URLSearchParams({
                command:raw
            })
        }
    );

    const d=await r.json();

    document.getElementById(
        'out'
    ).textContent +=
        `\n> ${raw}\n${d.output}\n`;

    document.getElementById(
        'out'
    ).scrollTop=
        document.getElementById(
            'out'
        ).scrollHeight;

    el.value='';
}

{% endif %}

</script>
'''


STAFF_DETAIL = r'''
<div class="hero">

<div class="pill">
STAFF CONTROL CENTER
·
{{role.upper()}}
</div>

<h1>
#{{row.id}}
·
{{row.web_name}}
</h1>

<p class="muted">
{{row.name}}
·
{{row.email}}
·
{{row.target}}
</p>

<span class="pill">
{{row.status}}
</span>

</div>


<div class="grid">

<div class="card">

<h3>
Request
</h3>

<p>
<b>Scope:</b>
{{row.scope}}
</p>

<p>
<b>Created:</b>
{{row.created_at}}
</p>

<p>
<b>Client IP:</b>
{{row.client_ip or 'not recorded'}}
</p>

</div>


<div class="card">

<h3>
Lifecycle
</h3>

<div class="links">

<form
    method="post"
    action="/staff/client/{{row.id}}/status"
>

<button
    class="btn primary"
    name="action"
    value="accept"
>
ACCEPT
</button>

<button
    class="btn"
    name="action"
    value="decline"
>
DECLINE
</button>

<button
    class="btn"
    name="action"
    value="reopen"
>
REOPEN
</button>

<button
    class="btn"
    name="action"
    value="start"
>
START ASSESSMENT
</button>

<button
    class="btn"
    name="action"
    value="complete"
>
MARK COMPLETED
</button>

</form>

</div>

</div>

</div>


<div
    class="split"
    style="margin-top:18px"
>


<div>

<div class="card">

<h2>
Live Chat
</h2>

<div
    style="
        max-height:420px;
        overflow:auto
    "
>

{% for m in messages %}

<div class="msg">

<b>
{{m.sender}}
</b>

<div>
{{m.message}}
</div>

<div class="mini muted">
{{m.created_at}}
</div>

</div>

{% else %}

<p class="muted">
No messages yet.
</p>

{% endfor %}

</div>


<form
    method="post"
    action="/staff/client/{{row.id}}/message"
>

<textarea
    name="message"
    placeholder="Reply to client..."
></textarea>

<button
    class="btn primary"
>
Send Message
</button>

</form>

</div>

</div>


<div>


<div class="card">

<h2>
Publish Finding
</h2>

<form
    method="post"
    action="/staff/client/{{row.id}}/finding"
>

<label>
Title
</label>

<input
    name="title"
    required
>

<label>
Severity
</label>

<select name="severity">

{% for s in [
    'INFO',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
] %}

<option>
{{s}}
</option>

{% endfor %}

</select>


<label>
Description
</label>

<textarea
    name="description"
    required
></textarea>


<label>
Evidence
</label>

<textarea
    name="evidence"
></textarea>


<label>
Recommendation
</label>

<textarea
    name="recommendation"
></textarea>


<button
    class="btn primary"
>
Publish Finding
</button>

</form>

</div>


<div
    class="card"
    style="margin-top:18px"
>

<h2>
Report
</h2>

<p class="muted">
{{findings|length}}
finding(s) published.
</p>

<a
    class="btn"
    href="/staff/client/{{row.id}}/report"
>
Open Report
</a>

</div>


</div>

</div>


<script>

setTimeout(
    ()=>location.reload(),
    7000
);

</script>
'''


STAFF_REPORT = r'''
<div class="hero">

<div class="pill">
STAFF REPORT
</div>

<h1>
{{row.web_name}}
</h1>

<p class="muted">
#{{row.id}}
·
{{row.target}}
·
{{row.status}}
</p>

</div>


<div class="card">

<p>
<b>Client:</b>
{{row.name}}
·
{{row.email}}
</p>

<p>
<b>Scope:</b>
{{row.scope}}
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

<div class="sev {{f.severity}}">
{{f.severity}}
·
{{f.title}}
</div>

<p>
{{f.description}}
</p>

<div class="mono">
{{f.evidence or ''}}
</div>

<p class="muted">
{{f.recommendation or ''}}
</p>

</div>

{% else %}

<p class="muted">
No findings.
</p>

{% endfor %}

</div>
'''


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "10000",
            )
        ),
    )
