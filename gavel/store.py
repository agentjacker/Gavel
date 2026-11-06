"""Durable, organization-scoped triage queue and audit trail."""

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


DEFAULT_POLICY = {
    "version": 1,
    "critical_assets": [],
    "acceptances": [],
    "max_context_age_hours": 24,
    "auto_route": False,
}


class Store:
    def __init__(self, database: str, organization_id: str):
        self.database = database
        self.organization_id = organization_id
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    organization_id TEXT NOT NULL, id TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL, title TEXT NOT NULL,
                    description TEXT NOT NULL, asset_id TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, decision TEXT,
                    generation INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (organization_id, id)
                );
                CREATE TABLE IF NOT EXISTS policies (
                    organization_id TEXT PRIMARY KEY, body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL, at TEXT NOT NULL,
                    action TEXT NOT NULL, object_id TEXT NOT NULL, details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    organization_id TEXT NOT NULL, id TEXT NOT NULL,
                    report_id TEXT NOT NULL, graph_revision TEXT NOT NULL,
                    destination TEXT NOT NULL, payload TEXT NOT NULL,
                    state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0,
                    last_error TEXT, created_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, id)
                );
                CREATE INDEX IF NOT EXISTS reports_queue
                    ON reports(organization_id, status, created_at);
            """
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _audit(self, db, action: str, object_id: str, details: Dict):
        db.execute(
            "INSERT INTO audit(organization_id, at, action, object_id, details) VALUES(?,?,?,?,?)",
            (self.organization_id, now(), action, object_id, json.dumps(details)),
        )

    def submit(self, title: str, description: str, asset_id: str) -> Dict:
        report_id, receipt = secrets.token_hex(16), secrets.token_urlsafe(32)
        timestamp = now()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute(
                "SELECT count(*) FROM reports WHERE organization_id=? AND status IN ('queued','analyzing')",
                (self.organization_id,),
            ).fetchone()[0]
            if count >= 1000:
                raise OverflowError("Submission queue is full")
            db.execute(
                "INSERT INTO reports(organization_id,id,receipt_hash,title,description,asset_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    self.organization_id,
                    report_id,
                    digest(receipt),
                    title,
                    description,
                    asset_id,
                    "queued",
                    timestamp,
                    timestamp,
                ),
            )
            self._audit(
                db, "report.submitted", report_id, {"content_hash": digest(description)}
            )
        return {
            "id": report_id,
            "receipt_token": receipt,
            "status": "queued",
            "message": "Report received and queued for contextual analysis. Save your private receipt token.",
        }

    @staticmethod
    def _report(row) -> Optional[Dict]:
        if row is None:
            return None
        result = dict(row)
        result.pop("receipt_hash", None)
        result.pop("organization_id", None)
        result["decision"] = (
            json.loads(result["decision"]) if result["decision"] else None
        )
        return result

    def report(self, report_id: str) -> Optional[Dict]:
        with self.connect() as db:
            return self._report(
                db.execute(
                    "SELECT * FROM reports WHERE organization_id=? AND id=?",
                    (self.organization_id, report_id),
                ).fetchone()
            )

    def public_report(self, report_id: str, receipt: str) -> Optional[Dict]:
        with self.connect() as db:
            row = db.execute(
                "SELECT receipt_hash,status,decision FROM reports WHERE organization_id=? AND id=?",
                (self.organization_id, report_id),
            ).fetchone()
        if not row or not secrets.compare_digest(row["receipt_hash"], digest(receipt)):
            return None
        status = row["status"]
        # Fixed text is the public boundary. Never return model text, topology, owners or code.
        messages = {
            "queued": "Report received and queued for analysis.",
            "analyzing": "Your report is being evaluated.",
            "review": "Analysis is complete. The security team is reviewing the outcome.",
            "routed": "Your report has been referred to the responsible security team.",
        }
        result = {
            "id": report_id,
            "status": status,
            "message": messages.get(status, messages["review"]),
        }
        if row["decision"]:
            decision = json.loads(row["decision"])
            if decision["validity"] == "supported":
                result["outcome"] = "evidence_supported"
                result["message"] = (
                    "Source evidence supports your report. The security team is reviewing its impact and next steps."
                )
            elif decision["validity"] == "refuted" and not decision.get(
                "missing_evidence"
            ):
                result["outcome"] = "not_supported_by_current_evidence"
                result["message"] = (
                    "The current evidence does not support the reported behavior. The security team is reviewing this assessment."
                )
            else:
                result["outcome"] = "requires_review"
                result["message"] = (
                    "The available evidence is inconclusive. Your report requires security team review."
                )
        return result

    def reports(self):
        with self.connect() as db:
            return [
                self._report(row)
                for row in db.execute(
                    "SELECT * FROM reports WHERE organization_id=? ORDER BY created_at DESC LIMIT 500",
                    (self.organization_id,),
                )
            ]

    def decisions(self):
        """Complete security dataset, separate from the bounded UI inbox.

        Excludes raw report bodies and receipts. The path engine applies its own
        explicit capability bound and returns uncertainty when it is exceeded.
        """
        with self.connect() as db:
            return [
                {**dict(row), "decision": json.loads(row["decision"])}
                for row in db.execute(
                    "SELECT id,asset_id,generation,status,decision FROM reports WHERE organization_id=? AND decision IS NOT NULL ORDER BY created_at",
                    (self.organization_id,),
                )
            ]

    def inbox(self):
        """Bounded summaries; source evidence and full prose are fetched by ID."""
        reports, size, truncated = [], 100, False
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,title,asset_id,status,created_at,updated_at,decision FROM reports WHERE organization_id=? ORDER BY created_at DESC LIMIT 501",
                (self.organization_id,),
            )
            for row in rows:
                if len(reports) >= 500:
                    truncated = True
                    break
                item = dict(row)
                if item["decision"]:
                    decision = json.loads(item["decision"])
                    item["decision"] = {
                        key: decision.get(key)
                        for key in (
                            "validity",
                            "applicability",
                            "disposition",
                            "priority",
                            "owner",
                            "latent",
                        )
                    }
                    item["decision"]["summary"] = decision.get("summary", "")[:400]
                    item["decision"]["primitives"] = [
                        {
                            key: primitive.get(key)
                            for key in ("id", "asset_id", "fingerprint")
                        }
                        for primitive in decision.get("primitives", [])
                    ]
                encoded = len(json.dumps(item).encode()) + 2
                if size + encoded > 1_500_000:
                    truncated = True
                    break
                size += encoded
                reports.append(item)
        return {"reports": reports, "truncated": truncated}

    def claim(self) -> Optional[Dict]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM reports WHERE organization_id=? AND status='queued' ORDER BY created_at LIMIT 1",
                (self.organization_id,),
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE reports SET status='analyzing',updated_at=? WHERE organization_id=? AND id=?",
                    (now(), self.organization_id, row["id"]),
                )
            return self._report(row)

    def recover(self):
        with self.connect() as db:
            db.execute(
                "UPDATE reports SET status='queued' WHERE organization_id=? AND status='analyzing'",
                (self.organization_id,),
            )
            # Unknown delivery after a crash is retried with the same idempotency key.
            db.execute(
                "UPDATE outbox SET state='pending' WHERE organization_id=? AND state='sending'",
                (self.organization_id,),
            )

    def finish(self, report_id: str, generation: int, decision: Dict) -> bool:
        with self.connect() as db:
            updated = db.execute(
                "UPDATE reports SET decision=?,status='review',updated_at=? WHERE organization_id=? AND id=? AND generation=? AND status='analyzing'",
                (
                    json.dumps(decision),
                    now(),
                    self.organization_id,
                    report_id,
                    generation,
                ),
            ).rowcount
            if updated:
                self._audit(
                    db,
                    "report.analyzed",
                    report_id,
                    {
                        "graph_revision": decision["graph_revision"],
                        "validity": decision["validity"],
                        "policy_version": decision["policy_version"],
                    },
                )
            return bool(updated)

    def requeue(self, report_id: Optional[str] = None) -> int:
        with self.connect() as db:
            query = "UPDATE reports SET status='queued',decision=NULL,generation=generation+1,updated_at=? WHERE organization_id=?"
            args = [now(), self.organization_id]
            if report_id:
                query += " AND id=?"
                args.append(report_id)
            count = db.execute(query, args).rowcount
            # A superseded analysis must never dispatch an old decision.
            cancel = "UPDATE outbox SET state='cancelled' WHERE organization_id=? AND state IN ('pending','failed')"
            cancel_args = [self.organization_id]
            if report_id:
                cancel += " AND report_id=?"
                cancel_args.append(report_id)
            db.execute(cancel, cancel_args)
            self._audit(db, "reports.requeued", report_id or "*", {"count": count})
            return count

    def policy(self) -> Dict:
        with self.connect() as db:
            row = db.execute(
                "SELECT body FROM policies WHERE organization_id=?",
                (self.organization_id,),
            ).fetchone()
            return json.loads(row[0]) if row else dict(DEFAULT_POLICY)

    def save_policy(self, policy: Dict) -> Dict:
        from gavel.triage import validate_policy

        policy = validate_policy(policy)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT body FROM policies WHERE organization_id=?",
                (self.organization_id,),
            ).fetchone()
            policy["version"] = (json.loads(row[0])["version"] if row else 1) + 1
            db.execute(
                "INSERT OR REPLACE INTO policies VALUES(?,?)",
                (self.organization_id, json.dumps(policy)),
            )
            self._audit(
                db,
                "policy.updated",
                str(policy["version"]),
                {"hash": digest(json.dumps(policy, sort_keys=True))},
            )
        self.requeue()
        return policy

    def enqueue_delivery(self, report_id: str, destination: str) -> Dict:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            report = self._report(
                db.execute(
                    "SELECT * FROM reports WHERE organization_id=? AND id=?",
                    (self.organization_id, report_id),
                ).fetchone()
            )
            if (
                not report
                or report["status"] not in ("review", "routed")
                or not report["decision"]
            ):
                raise ValueError("Report needs a completed analysis")
            decision = report["decision"]
            if decision["validity"] != "supported" or decision["disposition"] not in (
                "fix",
                "monitor",
            ):
                raise ValueError("Only evidence-supported findings can be routed")
            event_id = digest(
                json.dumps(
                    [
                        report_id,
                        report["generation"],
                        decision["graph_revision"],
                        decision["policy_version"],
                        decision["priority"],
                        decision["disposition"],
                        decision.get("capabilities_gained", []),
                        destination,
                    ],
                    sort_keys=True,
                )
            )
            payload = {
                "event_id": event_id,
                "report_id": report_id,
                "asset_id": report["asset_id"],
                "priority": decision["priority"],
                "owner": decision.get("owner"),
                "disposition": decision["disposition"],
                "graph_revision": decision["graph_revision"],
            }
            # Untrusted report prose and model text never become Slack/Jira markup.
            db.execute(
                "UPDATE outbox SET state='cancelled' WHERE organization_id=? AND report_id=? AND destination=? AND id<>? AND state IN ('pending','failed')",
                (self.organization_id, report_id, destination, event_id),
            )
            db.execute(
                "INSERT INTO outbox(organization_id,id,report_id,graph_revision,destination,payload,state,created_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(organization_id,id) DO UPDATE SET state='pending',attempts=0,next_attempt=0,last_error=NULL WHERE outbox.state='cancelled'",
                (
                    self.organization_id,
                    event_id,
                    report_id,
                    decision["graph_revision"],
                    destination,
                    json.dumps(payload),
                    "pending",
                    now(),
                ),
            )
            db.execute(
                "UPDATE reports SET status='routed' WHERE organization_id=? AND id=?",
                (self.organization_id, report_id),
            )
            self._audit(
                db,
                "delivery.approved",
                report_id,
                {"event_id": event_id, "destination": destination},
            )
        return payload

    def outbox(self):
        with self.connect() as db:
            return [
                {**dict(row), "payload": json.loads(row["payload"])}
                for row in db.execute(
                    "SELECT id,report_id,destination,state,attempts,last_error,created_at,payload FROM outbox WHERE organization_id=? ORDER BY created_at DESC LIMIT 500",
                    (self.organization_id,),
                )
            ]

    def audit(self):
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT seq,at,action,object_id,details FROM audit WHERE organization_id=? ORDER BY seq DESC LIMIT 500",
                    (self.organization_id,),
                )
            ]
