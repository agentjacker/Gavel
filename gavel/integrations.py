"""Operator-configured destinations and a retryable outbox.

Delivery is at least once. Jira/Slack do not provide a universal transactional
deduplication API; the stable event ID makes downstream deduplication possible.
"""

import json
import os
import re
import time
from urllib.parse import urlsplit


def validate_destinations(destinations):
    if not isinstance(destinations, dict) or set(destinations) - {"slack", "jira"}:
        raise ValueError("Destinations must be named slack or jira")
    for name, settings in destinations.items():
        if name == "slack":
            url = os.environ.get(settings["url_env"], "")
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname != "hooks.slack.com"
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
                or parsed.query
                or parsed.fragment
                or not parsed.path.startswith("/services/")
            ):
                raise ValueError(
                    "Slack requires a hooks.slack.com HTTPS webhook in its configured environment variable"
                )
        else:
            parsed = urlsplit(settings["base_url"])
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                raise ValueError("Jira base_url must be an HTTPS origin")
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,30}", settings["project_key"]):
                raise ValueError("Invalid Jira project key")
            if not os.environ.get(settings["token_env"]) or not os.environ.get(
                settings["email_env"]
            ):
                raise ValueError(
                    "Jira credentials must be supplied in configured environment variables"
                )


def send_event(name, settings, payload):
    import requests

    text = (
        "Gavel finding "
        + payload["report_id"]
        + " | asset: "
        + payload["asset_id"]
        + " | owner: "
        + (payload.get("owner") or "security triage")
        + " | action: "
        + payload["priority"]
        + " | disposition: "
        + payload["disposition"]
        + " | event: "
        + payload["event_id"]
    )
    if name == "slack":
        url = os.environ[settings["url_env"]]
        body = {
            "text": text,
            "unfurl_links": False,
            "unfurl_media": False,
            "blocks": [
                {"type": "section", "text": {"type": "plain_text", "text": text}}
            ],
        }
        auth = None
    else:
        url = settings["base_url"].rstrip("/") + "/rest/api/3/issue"
        fields = {
            "project": {"key": settings["project_key"]},
            "issuetype": {"name": settings.get("issue_type", "Task")},
            "summary": "Gavel security finding " + payload["report_id"],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": text}]}
                ],
            },
        }
        owner = settings.get("owner_map", {}).get(payload.get("owner"))
        if owner:
            fields["assignee"] = {"accountId": owner}
        body, auth = {"fields": fields}, (
            os.environ[settings["email_env"]],
            os.environ[settings["token_env"]],
        )
    with requests.post(
        url,
        json=body,
        auth=auth,
        headers={"Idempotency-Key": payload["event_id"]},
        timeout=(5, 20),
        allow_redirects=False,
        stream=True,
    ) as response:
        if not 200 <= response.status_code < 300:
            # Do not persist remote response text, credentials, webhook URLs or private tickets.
            raise RuntimeError("Destination returned HTTP " + str(response.status_code))


def dispatch_one(store, destinations, graph_revision):
    timestamp = time.time()
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        event = db.execute(
            "SELECT * FROM outbox WHERE organization_id=? AND state='pending' AND next_attempt<=? ORDER BY created_at LIMIT 1",
            (store.organization_id, timestamp),
        ).fetchone()
        if not event:
            return False
        if event["graph_revision"] != graph_revision:
            db.execute(
                "UPDATE outbox SET state='cancelled' WHERE organization_id=? AND id=?",
                (store.organization_id, event["id"]),
            )
            return True
        db.execute(
            "UPDATE outbox SET state='sending',attempts=attempts+1 WHERE organization_id=? AND id=?",
            (store.organization_id, event["id"]),
        )
    state, error = "delivered", None
    try:
        settings = destinations[event["destination"]]
        send_event(event["destination"], settings, json.loads(event["payload"]))
    except Exception:
        state = "failed" if event["attempts"] >= 4 else "pending"
        error = "Delivery failed; verify destination and credentials."
    with store.connect() as db:
        db.execute(
            "UPDATE outbox SET state=?,last_error=?,next_attempt=? WHERE organization_id=? AND id=?",
            (
                state,
                error,
                timestamp + min(3600, 2 ** (event["attempts"] + 1) * 15),
                store.organization_id,
                event["id"],
            ),
        )
        store._audit(
            db, "delivery." + state, event["report_id"], {"event_id": event["id"]}
        )
    return True
