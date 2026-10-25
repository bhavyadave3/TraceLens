from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "evidence.db"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = FastAPI(
    title="TraceLens API",
    description="Rule-based digital evidence triage and investigation support.",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE AND LEGACY DATABASE FIXES
# ============================================================

def get_connection() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _integer_id_pk(con: sqlite3.Connection) -> bool:
    for col in con.execute("PRAGMA table_info(cases)").fetchall():
        if col["name"] == "id":
            return bool(
                col["pk"]
                and "INT" in (col["type"] or "").upper()
            )
    return False


def init_db() -> None:
    """
    Create the current table and migrate older database columns and IDs.
    Existing investigation records are preserved.
    """
    with get_connection() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL DEFAULT '',
                uploaded_at TEXT NOT NULL DEFAULT '',
                event_count INTEGER NOT NULL DEFAULT 0,
                flagged_count INTEGER NOT NULL DEFAULT 0,
                findings_json TEXT NOT NULL DEFAULT '[]',
                events_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )

        info = con.execute("PRAGMA table_info(cases)").fetchall()
        cols = {row["name"] for row in info}

        definitions = {
            "id": "TEXT",
            "filename": "TEXT NOT NULL DEFAULT ''",
            "sha256": "TEXT NOT NULL DEFAULT ''",
            "uploaded_at": "TEXT NOT NULL DEFAULT ''",
            "event_count": "INTEGER NOT NULL DEFAULT 0",
            "flagged_count": "INTEGER NOT NULL DEFAULT 0",
            "findings_json": "TEXT NOT NULL DEFAULT '[]'",
            "events_json": "TEXT NOT NULL DEFAULT '[]'",
        }

        for name, definition in definitions.items():
            if name not in cols:
                con.execute(
                    f'ALTER TABLE cases ADD COLUMN "{name}" {definition}'
                )

        info = con.execute("PRAGMA table_info(cases)").fetchall()
        col_info = {row["name"]: row for row in info}
        cols = set(col_info)

        # Copy existing hashes from older column names.
        hash_old = next(
            (
                name
                for name in (
                    "file_hash",
                    "hash_sha256",
                    "file_sha256",
                    "hash",
                )
                if name in cols
            ),
            None,
        )

        if hash_old:
            con.execute(
                f"""
                UPDATE cases
                SET sha256 = CAST("{hash_old}" AS TEXT)
                WHERE COALESCE(sha256, '') = ''
                  AND COALESCE(
                      CAST("{hash_old}" AS TEXT), ''
                  ) <> ''
                """
            )

        # Copy upload dates from older column names.
        date_old = next(
            (
                name
                for name in (
                    "created_at",
                    "upload_date",
                    "date_uploaded",
                    "created",
                )
                if name in cols
            ),
            None,
        )

        if date_old:
            con.execute(
                f"""
                UPDATE cases
                SET uploaded_at = CAST("{date_old}" AS TEXT)
                WHERE COALESCE(uploaded_at, '') = ''
                  AND COALESCE(
                      CAST("{date_old}" AS TEXT), ''
                  ) <> ''
                """
            )

        # Repair missing IDs in older databases using text IDs.
        id_col = col_info.get("id")

        int_pk = bool(
            id_col
            and id_col["pk"]
            and "INT" in (id_col["type"] or "").upper()
        )

        if not int_pk:
            missing = con.execute(
                """
                SELECT rowid
                FROM cases
                WHERE id IS NULL OR CAST(id AS TEXT) = ''
                """
            ).fetchall()

            for item in missing:
                rowid = int(item["rowid"])
                new_id = f"legacy-{rowid}"

                duplicate = con.execute(
                    """
                    SELECT 1
                    FROM cases
                    WHERE CAST(id AS TEXT) = ?
                    LIMIT 1
                    """,
                    (new_id,),
                ).fetchone()

                if duplicate:
                    new_id = (
                        f"legacy-{rowid}-{uuid.uuid4().hex[:6]}"
                    )

                con.execute(
                    "UPDATE cases SET id = ? WHERE rowid = ?",
                    (new_id, rowid),
                )

        con.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cases_uploaded_at
            ON cases(uploaded_at DESC)
            """
        )

        con.commit()


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _key(value: Any) -> str:
    return re.sub(
        r"[^a-z0-9]",
        "",
        str(value or "").lower().lstrip("\ufeff"),
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = _text(value)

        if not raw:
            return None

        try:
            parsed = datetime.fromisoformat(
                raw.replace("Z", "+00:00")
            )
        except ValueError:
            parsed = None

        if parsed is None:
            formats = (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%d-%m-%Y %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            )

            for fmt in formats:
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    pass

        if parsed is None:
            return None

    if parsed.tzinfo:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _json_ready(item)
            for key, item in value.items()
            if key != "timestamp_parsed"
        }

    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]

    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def _deduplicate(items: list[str]) -> list[str]:
    seen = set()
    output = []

    for item in items:
        if item and item not in seen:
            output.append(item)
            seen.add(item)

    return output


def _severity(score: int | float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


# ============================================================
# CSV NORMALIZATION
# ============================================================

def normalize_event(
    row: dict[str, Any],
    index: int = 1,
) -> dict[str, Any]:

    lookup = {
        _key(key): value
        for key, value in row.items()
        if key is not None
    }

    def take(*names: str) -> str:
        for name in names:
            value = lookup.get(_key(name))
            if value is not None and _text(value):
                return _text(value)
        return ""

    timestamp = take(
        "timestamp",
        "time",
        "event_time",
        "datetime",
        "date_time",
        "created_at",
        "event_timestamp",
        "timestamp_utc",
        "ts",
        "timecreated",
    )

    parsed = _parse_timestamp(timestamp)

    username = take(
        "username",
        "user_name",
        "user",
        "actor",
        "principal",
        "identity",
        "user_id",
        "account",
        "account_name",
        "caller",
        "principal_id",
    ) or "unknown"

    source_ip = take(
        "source_ip",
        "sourceip",
        "ip",
        "ip_address",
        "client_ip",
        "remote_ip",
        "src_ip",
        "source_address",
        "ipaddress",
        "caller_ip",
        "sourceipaddress",
    ) or "unknown"

    event_type = take(
        "event_type",
        "event_name",
        "eventname",
        "action",
        "operation",
        "activity",
        "event",
        "api_action",
        "operation_name",
        "api_name",
    ) or "unknown_event"

    status = take(
        "status",
        "result",
        "outcome",
        "response",
        "authentication_result",
        "login_status",
        "success",
        "event_status",
    ) or "unknown"

    event_source = take(
        "event_source",
        "eventsource",
        "service",
        "provider",
        "source",
        "cloud_service",
        "resource_type",
    )

    if not timestamp and parsed:
        timestamp = parsed.isoformat(timespec="seconds")

    return {
        "id": index,
        "event_id": index,
        "timestamp": timestamp,
        "timestamp_parsed": parsed,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "event_name": event_type,
        "event_source": event_source,
        "status": status,
        "flagged": False,
        "score": 0,
        "severity": "None",
        "reasons": [],
        "raw": {
            str(key): value
            for key, value in row.items()
            if key is not None
        },
    }


# ============================================================
# INDIVIDUAL EVENT ANALYSIS
# ============================================================

def analyze_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag potential investigation leads using transparent rules."""

    reasons_by_id: dict[int, list[str]] = defaultdict(list)
    scores: dict[int, int] = defaultdict(int)

    def add(
        event: dict[str, Any],
        score: int,
        reason: str,
    ) -> None:
        event_id = int(
            event.get("id", event.get("event_id", 0))
        )
        reasons_by_id[event_id].append(reason)
        scores[event_id] = max(scores[event_id], score)

    def event_text(event: dict[str, Any]) -> str:
        raw = json.dumps(
            event.get("raw", {}),
            ensure_ascii=False,
            default=str,
        )

        return (
            f"{event.get('event_type', '')} "
            f"{event.get('event_name', '')} "
            f"{event.get('event_source', '')} "
            f"{event.get('status', '')} {raw}"
        ).lower()

    def auth_related(event: dict[str, Any]) -> bool:
        text = event_text(event)

        return any(term in text for term in (
            "login",
            "log_in",
            "signin",
            "sign_in",
            "authenticate",
            "authentication",
            "authn",
            "consolelogin",
            "console_login",
        ))

    def failed_auth(event: dict[str, Any]) -> bool:
        if not auth_related(event):
            return False

        status = _text(event.get("status")).lower()
        detail = event_text(event)

        return (
            any(term in status for term in (
                "fail",
                "denied",
                "invalid",
                "reject",
                "unsuccessful",
                "error",
            ))
            or any(term in detail for term in (
                "failed_login",
                "login_failed",
                "authenticationfailure",
                "authentication_failure",
                "invalidpassword",
            ))
        )

    def successful_auth(event: dict[str, Any]) -> bool:
        if not auth_related(event):
            return False

        status = _text(event.get("status")).lower()

        if any(term in status for term in (
            "fail",
            "denied",
            "invalid",
            "reject",
            "error",
        )):
            return False

        return any(term in status for term in (
            "success",
            "succeeded",
            "accepted",
            "allowed",
            "complete",
            "ok",
        ))

    # Rule 1: five or more failed logins within five minutes.
    failed_groups: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if failed_auth(event):
            key = (
                _text(event.get("username")).lower(),
                _text(event.get("source_ip")).lower(),
            )
            failed_groups[key].append(event)

    for group in failed_groups.values():
        timed = sorted(
            (
                event for event in group
                if event.get("timestamp_parsed")
            ),
            key=lambda event: event["timestamp_parsed"],
        )

        for end_index, end_event in enumerate(timed):
            end_time = end_event["timestamp_parsed"]

            window = [
                event
                for event in timed[:end_index + 1]
                if 0 <= (
                    end_time - event["timestamp_parsed"]
                ).total_seconds() <= 300
            ]

            if len(window) >= 5:
                reason = (
                    f"At least {len(window)} failed authentication attempts "
                    "occurred for the same username and source IP "
                    "within five minutes."
                )

                for event in window:
                    add(event, 70, reason)

    # Rule 2: successful authentication after failed attempts.
    failures_by_identity: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for event in events:
        if failed_auth(event):
            key = (
                _text(event.get("username")).lower(),
                _text(event.get("source_ip")).lower(),
            )
            failures_by_identity[key].append(event)

    for event in events:
        timestamp = event.get("timestamp_parsed")

        if not successful_auth(event) or not timestamp:
            continue

        key = (
            _text(event.get("username")).lower(),
            _text(event.get("source_ip")).lower(),
        )

        prior_failures = [
            failure
            for failure in failures_by_identity.get(key, [])
            if failure.get("timestamp_parsed")
            and 0 <= (
                timestamp - failure["timestamp_parsed"]
            ).total_seconds() <= 600
        ]

        if prior_failures:
            add(
                event,
                55,
                "A successful authentication occurred within ten minutes "
                "after failed attempts for the same username and source IP.",
            )

    # Rule 3: potentially sensitive administrative and audit actions.
    for event in events:
        detail = event_text(event).replace("-", "_").replace(" ", "_")

        audit_risk = (
            (
                "delete" in detail
                and any(
                    word in detail
                    for word in ("trail", "audit", "log")
                )
            )
            or "stoplogging" in detail
            or "stop_logging" in detail
            or (
                "disable" in detail
                and any(
                    word in detail
                    for word in ("logging", "audit", "trail")
                )
            )
        )

        permission_risk = any(word in detail for word in (
            "permission",
            "policy",
            "accesskey",
            "access_key",
            "privilege",
            "admin",
            "attachuserpolicy",
            "createaccesskey",
            "rolechange",
            "role_change",
        ))

        if audit_risk:
            add(
                event,
                55,
                "The event may delete, disable, or stop audit/logging "
                "records; verify whether the action was authorized.",
            )
        elif permission_risk:
            add(
                event,
                45,
                "The event may change permissions, policies, roles, or "
                "access privileges; verify authorization and scope.",
            )

    # Rule 4: successful logins during unusual UTC hours.
    for event in events:
        timestamp = event.get("timestamp_parsed")

        if (
            successful_auth(event)
            and timestamp
            and (timestamp.hour < 6 or timestamp.hour >= 22)
        ):
            add(
                event,
                35,
                "A successful authentication occurred during an unusual "
                "UTC hour (before 06:00 or at/after 22:00).",
            )

    findings = []
    flagged_ids = set()

    for event in events:
        event_id = int(
            event.get("id", event.get("event_id", 0))
        )
        reasons = _deduplicate(reasons_by_id.get(event_id, []))

        if not reasons:
            continue

        score = min(100, scores[event_id])
        finding = dict(event)
        finding.update({
            "flagged": True,
            "score": score,
            "severity": _severity(score),
            "reasons": reasons,
            "finding_id": f"F-{event_id:04d}",
        })

        findings.append(finding)
        flagged_ids.add(event_id)

    for event in events:
        event_id = int(
            event.get("id", event.get("event_id", 0))
        )

        if event_id in flagged_ids:
            event.update({
                "flagged": True,
                "score": scores[event_id],
                "severity": _severity(scores[event_id]),
                "reasons": _deduplicate(
                    reasons_by_id[event_id]
                ),
            })

    findings.sort(
        key=lambda item: (
            item.get("timestamp_parsed") or datetime.min,
            -int(item.get("score", 0)),
        )
    )

    return findings


# ============================================================
# CORRELATION SCORING
# ============================================================

def apply_correlation_scoring(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Score groups of flagged events sharing the same username and IP."""

    groups: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for item in findings:
        username = _text(
            item.get("username", item.get("user"))
        ).lower()

        source_ip = _text(
            item.get(
                "source_ip",
                item.get("sourceIp", item.get("ip_address")),
            )
        ).lower()

        if (
            not username
            or not source_ip
            or username in {"unknown", "n/a", "none"}
            or source_ip in {"unknown", "n/a", "none"}
        ):
            item.update({
                "correlation_score": 0,
                "correlation_level": "Uncorrelated",
                "correlation_reasons": [
                    "Username or source IP is missing, so this event was not grouped."
                ],
            })
            continue

        groups[(username, source_ip)].append(item)

    for group in groups.values():
        if len(group) < 2:
            group[0].update({
                "correlation_score": 0,
                "correlation_level": "Uncorrelated",
                "correlation_reasons": [
                    "No second flagged event was found for this username and source IP."
                ],
            })
            continue

        records = []

        for item in group:
            name = _text(
                item.get("event_type", item.get("event_name"))
            ).lower()

            status = _text(item.get("status")).lower()

            timestamp = _parse_timestamp(
                item.get("timestamp_parsed")
                or item.get("timestamp")
            )

            combined = f"{name} {status}".replace("-", "_")

            is_login = any(word in combined for word in (
                "login",
                "log_in",
                "signin",
                "sign_in",
                "authentication",
                "auth",
            ))

            is_success = (
                any(word in status for word in (
                    "success",
                    "succeeded",
                    "allowed",
                    "accepted",
                    "complete",
                    "ok",
                ))
                and not any(word in status for word in (
                    "fail",
                    "denied",
                    "invalid",
                    "reject",
                    "error",
                ))
            )

            is_permission = any(word in combined for word in (
                "permission",
                "policy",
                "privilege",
                "role",
                "accesskey",
                "admin",
            ))

            is_audit_risk = (
                (
                    "delete" in combined
                    and any(
                        word in combined
                        for word in ("trail", "audit", "log")
                    )
                )
                or "stoplogging" in combined
                or "stop_logging" in combined
                or (
                    "disable" in combined
                    and any(
                        word in combined
                        for word in ("logging", "audit", "trail")
                    )
                )
            )

            records.append({
                "time": timestamp,
                "login": is_login and is_success,
                "permission": is_permission,
                "audit": is_audit_risk,
            })

        # Base score plus event-category bonuses.
        score = min(30, 15 + 5 * max(0, len(group) - 2))

        reasons = [
            f"{len(group)} flagged events share the same username and source IP."
        ]

        if any(record["login"] for record in records):
            score += 10
            reasons.append(
                "A successful login appears in the event group."
            )

        if any(record["permission"] for record in records):
            score += 20
            reasons.append(
                "The group contains a permission or privilege-related event."
            )

        if any(record["audit"] for record in records):
            score += 25
            reasons.append(
                "The group contains a potentially risky audit/logging action."
            )

        timeline = sorted(
            (
                record for record in records
                if record["time"] is not None
            ),
            key=lambda record: record["time"],
        )

        login = next(
            (record for record in timeline if record["login"]),
            None,
        )

        permission = next(
            (
                record for record in timeline
                if login
                and record["permission"]
                and record["time"] > login["time"]
            ),
            None,
        )

        audit = next(
            (
                record for record in timeline
                if permission
                and record["audit"]
                and record["time"] > permission["time"]
            ),
            None,
        )

        if login and permission and audit:
            duration = (
                audit["time"] - login["time"]
            ).total_seconds()

            if 0 <= duration <= 7200:
                score += 15
                reasons.append(
                    "Login, permission change, and audit/logging action "
                    "occurred in sequence within two hours."
                )

        score = min(100, score)

        if score >= 85:
            level = "Critical"
        elif score >= 65:
            level = "High"
        elif score >= 40:
            level = "Medium"
        else:
            level = "Low"

        for item in group:
            item.update({
                "correlation_score": score,
                "correlation_level": level,
                "correlation_reasons": reasons.copy(),
            })

    return findings


# ============================================================
# EVIDENCE STORYLINE
# ============================================================

def build_storylines(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for item in findings:
        username = _text(item.get("username")).lower()
        source_ip = _text(item.get("source_ip")).lower()

        if (
            username
            and source_ip
            and username != "unknown"
            and source_ip != "unknown"
        ):
            groups[(username, source_ip)].append(item)

    storylines = []

    for (username, source_ip), items in groups.items():
        if len(items) < 2:
            continue

        ordered = sorted(
            items,
            key=lambda item: (
                _parse_timestamp(item.get("timestamp"))
                or datetime.min
            ),
        )

        top = max(
            ordered,
            key=lambda item: int(
                item.get("correlation_score", 0)
            ),
        )

        storylines.append({
            "username": ordered[0].get("username", username),
            "source_ip": ordered[0].get("source_ip", source_ip),
            "event_count": len(ordered),
            "correlation_score": int(
                top.get("correlation_score", 0)
            ),
            "correlation_level": top.get(
                "correlation_level", "Uncorrelated"
            ),
            "reasons": ordered[0].get(
                "correlation_reasons", []
            ),
            "events": [
                {
                    "id": item.get("id"),
                    "timestamp": item.get("timestamp", ""),
                    "event_type": item.get(
                        "event_type",
                        item.get("event_name", "unknown_event"),
                    ),
                    "status": item.get("status", "unknown"),
                    "severity": item.get("severity", "Low"),
                    "score": item.get("score", 0),
                }
                for item in ordered
            ],
        })

    return sorted(
        storylines,
        key=lambda item: int(item.get("correlation_score", 0)),
        reverse=True,
    )


# ============================================================
# DATABASE INSERT AND LOOKUP HELPERS
# ============================================================

def insert_case_record(
    *,
    filename: str,
    sha256_digest: str,
    uploaded_at: str,
    event_count: int,
    flagged_count: int,
    findings_json: str,
    events_json: str,
) -> str:
    """Insert into old or current database schemas and return a usable ID."""

    values: dict[str, Any] = {
        "filename": filename,
        "original_filename": filename,
        "file_name": filename,
        "case_name": filename,

        "sha256": sha256_digest,
        "file_hash": sha256_digest,
        "hash_sha256": sha256_digest,
        "file_sha256": sha256_digest,
        "hash": sha256_digest,

        "uploaded_at": uploaded_at,
        "created_at": uploaded_at,
        "upload_date": uploaded_at,
        "date_uploaded": uploaded_at,
        "created": uploaded_at,

        "event_count": event_count,
        "total_events": event_count,
        "events_count": event_count,
        "record_count": event_count,

        "flagged_count": flagged_count,
        "total_flagged": flagged_count,
        "anomaly_count": flagged_count,
        "anomalies_count": flagged_count,

        "findings_json": findings_json,
        "analysis_json": findings_json,
        "findings": findings_json,

        "events_json": events_json,
        "timeline_json": events_json,
        "events": events_json,
    }

    with get_connection() as con:
        schema = con.execute("PRAGMA table_info(cases)").fetchall()
        integer_id = _integer_id_pk(con)

        # Legacy text-ID databases need IDs explicitly.
        if not integer_id:
            values["id"] = uuid.uuid4().hex[:8]

        inserts: dict[str, Any] = {}

        for column in schema:
            name = column["name"]
            dtype = (column["type"] or "").upper()

            if name in values:
                inserts[name] = values[name]
            elif name == "id" and integer_id:
                # SQLite auto-generates INTEGER PRIMARY KEY.
                continue
            elif (
                column["notnull"]
                and column["dflt_value"] is None
                and not column["pk"]
            ):
                # Supply a safe default for unused required legacy columns.
                if any(
                    kind in dtype
                    for kind in ("INT", "REAL", "NUM", "FLOAT", "DOUBLE")
                ):
                    inserts[name] = 0
                elif "BLOB" in dtype:
                    inserts[name] = b""
                else:
                    inserts[name] = ""

        if not inserts:
            raise sqlite3.OperationalError(
                "The cases table has no insertable columns."
            )

        names = ", ".join(
            '"' + name.replace('"', '""') + '"'
            for name in inserts
        )

        placeholders = ", ".join("?" for _ in inserts)

        cursor = con.execute(
            f"INSERT INTO cases ({names}) VALUES ({placeholders})",
            list(inserts.values()),
        )

        rowid = int(cursor.lastrowid)

        saved = con.execute(
            "SELECT id FROM cases WHERE rowid = ?",
            (rowid,),
        ).fetchone()

        con.commit()

        if saved and saved["id"] not in (None, ""):
            return str(saved["id"])

        return str(rowid)


def find_case_row(case_id: str) -> sqlite3.Row | None:
    """Find an investigation using its ID or SQLite row ID."""

    with get_connection() as con:
        return con.execute(
            """
            SELECT *
            FROM cases
            WHERE CAST(id AS TEXT) = ?
               OR CAST(rowid AS TEXT) = ?
            LIMIT 1
            """,
            (str(case_id), str(case_id)),
        ).fetchone()


# Migrate the database on application startup.
init_db()


# ============================================================
# API ENDPOINTS
# ============================================================

@app.get("/api/health")
def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "ok": True,
        "service": "TraceLens API",
        "database": (
            "connected" if DB_PATH.exists() else "initializing"
        ),
    }


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(...),
) -> dict[str, Any]:

    filename = Path(
        file.filename or "uploaded-log.csv"
    ).name

    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file.",
        )

    raw_file = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()

    if not raw_file:
        raise HTTPException(
            status_code=400,
            detail="The uploaded CSV file is empty.",
        )

    if len(raw_file) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail="The maximum upload size is 10 MB.",
        )

    digest = hashlib.sha256(raw_file).hexdigest()

    try:
        try:
            text = raw_file.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw_file.decode("latin-1")

        reader = csv.DictReader(io.StringIO(text))

        if not reader.fieldnames:
            raise HTTPException(
                status_code=400,
                detail="The CSV has no header row.",
            )

        events = [
            normalize_event(row, index)
            for index, row in enumerate(reader, start=1)
            if row and any(
                _text(value)
                for value in row.values()
                if value is not None
            )
        ]

    except csv.Error as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not read CSV: {exc}",
        ) from exc

    if not events:
        raise HTTPException(
            status_code=400,
            detail="No event records were found in the CSV.",
        )

    findings = apply_correlation_scoring(
        analyze_events(events)
    )

    findings_by_id = {
    int(item.get("id", item.get("event_id", 0))): item
    for item in findings
    }

    for event in events:
        event_id = int(
            event.get("id", event.get("event_id", 0))
        )

        finding = findings_by_id.get(event_id)

        if finding:
            for key in (
                "flagged",
                "score",
                "severity",
                "reasons",
                "correlation_score",
                "correlation_level",
                "correlation_reasons",
            ):
                event[key] = finding.get(key)

    safe_findings = _json_ready(findings)
    safe_events = _json_ready(events)

    uploaded_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    try:
        case_id = insert_case_record(
            filename=filename,
            sha256_digest=digest,
            uploaded_at=uploaded_at,
            event_count=len(safe_events),
            flagged_count=len(safe_findings),
            findings_json=json.dumps(
                safe_findings,
                ensure_ascii=False,
            ),
            events_json=json.dumps(
                safe_events,
                ensure_ascii=False,
            ),
        )

    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not save investigation: {exc}",
        ) from exc

    summary = {
        "id": case_id,
        "case_id": case_id,
        "filename": filename,
        "sha256": digest,
        "uploaded_at": uploaded_at,
        "event_count": len(safe_events),
        "flagged_count": len(safe_findings),
    }

    return {
        **summary,
        "case": summary,
        "findings": safe_findings,
        "events": safe_events,
        "storylines": build_storylines(safe_findings),
        "message": (
            "Analysis completed. Findings are investigation leads, "
            "not proof of malicious activity."
        ),
    }


@app.get("/api/cases")
def list_cases() -> dict[str, Any]:
    with get_connection() as con:
        rows = con.execute(
            """
            SELECT rowid AS _rowid_, *
            FROM cases
            ORDER BY rowid DESC
            """
        ).fetchall()

    cases = []

    for row in rows:
        item = dict(row)
        rowid = item.pop("_rowid_", None)

        case_id = item.get("id")

        if case_id in (None, ""):
            case_id = rowid

        item["id"] = (
            str(case_id) if case_id is not None else None
        )
        item["case_id"] = item["id"]

        if not item.get("sha256"):
            item["sha256"] = (
                item.get("file_hash")
                or item.get("hash_sha256")
                or ""
            )

        cases.append(item)

    return {
        "cases": cases,
        "count": len(cases),
    }


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    row = find_case_row(case_id)

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    keys = set(row.keys())
    findings = json.loads(row["findings_json"] or "[]")
    events = json.loads(row["events_json"] or "[]")

    public_id = (
        row["id"]
        if "id" in keys and row["id"] not in (None, "")
        else str(case_id)
    )

    digest = (
        (row["sha256"] if "sha256" in keys else "")
        or (row["file_hash"] if "file_hash" in keys else "")
        or (row["hash_sha256"] if "hash_sha256" in keys else "")
        or ""
    )

    summary = {
        "id": str(public_id),
        "case_id": str(public_id),
        "filename": (
            row["filename"] if "filename" in keys else ""
        ),
        "sha256": digest,
        "uploaded_at": (
            row["uploaded_at"] if "uploaded_at" in keys else ""
        ),
        "event_count": (
            row["event_count"]
            if "event_count" in keys
            else len(events)
        ),
        "flagged_count": (
            row["flagged_count"]
            if "flagged_count" in keys
            else len(findings)
        ),
    }

    return {
        **summary,
        "case": summary,
        "findings": findings,
        "events": events,
        "storylines": build_storylines(findings),
    }


@app.get("/api/cases/{case_id}/report")
def download_report(case_id: str) -> StreamingResponse:
    row = find_case_row(case_id)

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    findings = json.loads(row["findings_json"] or "[]")
    buffer = io.StringIO(newline="")

    fields = [
        "finding_id",
        "id",
        "timestamp",
        "username",
        "source_ip",
        "event_type",
        "event_source",
        "status",
        "severity",
        "score",
        "reasons",
        "correlation_level",
        "correlation_score",
        "correlation_reasons",
    ]

    writer = csv.DictWriter(
        buffer,
        fieldnames=fields,
        extrasaction="ignore",
    )
    writer.writeheader()

    for finding in findings:
        record = dict(finding)
        record["reasons"] = " | ".join(
            record.get("reasons", [])
        )
        record["correlation_reasons"] = " | ".join(
            record.get("correlation_reasons", [])
        )
        writer.writerow(record)

    safe_id = re.sub(
        r"[^A-Za-z0-9_-]",
        "_",
        str(case_id),
    )

    return StreamingResponse(
        io.BytesIO(buffer.getvalue().encode("utf-8-sig")),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="tracelens-case-{safe_id}-report.csv"'
            )
        },
    )