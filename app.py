@app.post("/api/staff/client/<int:request_id>/status")
@staff_required
def staff_status_api(request_id):
    row = get_request(request_id)

    if not row:
        return jsonify({"error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()

    transitions = {
        "accept": (
            ("PENDING",),
            "ACCEPTED",
            "Your security request has been ACCEPTED. Secure chat is now open."
        ),
        "decline": (
            ("PENDING", "ACCEPTED", "IN PROGRESS"),
            "DECLINED",
            "Your security request has been DECLINED."
        ),
        "reopen": (
            ("DECLINED",),
            "PENDING",
            "Your security request has been REOPENED and returned to review."
        ),
        "start": (
            ("ACCEPTED",),
            "IN PROGRESS",
            "Your assessment has STARTED. The security review is now in progress."
        ),
        "complete": (
            ("IN PROGRESS",),
            "COMPLETED",
            "Your assessment has been MARKED COMPLETED. Your report is available."
        ),
    }

    if action not in transitions:
        return jsonify({"error": "invalid_action"}), 400

    allowed_from, new_status, message = transitions[action]

    if row["status"] not in allowed_from:
        return jsonify({
            "error": "invalid_transition",
            "status": row["status"]
        }), 409

    conn = db()

    conn.execute(
        """
        UPDATE requests
        SET status=?,
            updated_at=?
        WHERE id=?
        """,
        (new_status, now(), request_id)
    )

    conn.commit()
    conn.close()

    system_message(request_id, message)

    notify(
        request_id,
        "CLIENT",
        "status",
        "Security request updated",
        message
    )

    notify(
        request_id,
        "STAFF",
        "status",
        "Client status changed",
        f"#{request_id} → {new_status}"
    )

    return jsonify({
        "ok": True,
        "status": new_status,
        "message": message
    })


@app.post("/api/staff/client/<int:request_id>/message")
@staff_required
def staff_message_api(request_id):
    row = get_request(request_id)

    if not row:
        return jsonify({"error": "not_found"}), 404

    if row["status"] not in (
        "ACCEPTED",
        "IN PROGRESS",
        "COMPLETED"
    ):
        return jsonify({
            "error": "chat_locked",
            "status": row["status"]
        }), 403

    data = request.get_json(silent=True) or {}

    message = str(
        data.get("message", "")
    ).strip()

    if not message:
        return jsonify({
            "error": "empty_message"
        }), 400

    if len(message) > 4000:
        return jsonify({
            "error": "message_too_long"
        }), 400

    actor = (
        "OWNER"
        if current_role() == "owner"
        else "ADMIN"
    )

    audit_action(
        request_id,
        actor,
        message,
        notify_client=True
    )

    return jsonify({
        "ok": True
    })
