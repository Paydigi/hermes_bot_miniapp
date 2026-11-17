"""Authenticated, per-user research records and preferences.

All identity comes from a validated server-side session. Callers cannot choose
or override the owner id. The store never accepts credentials or wallet secrets.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_TITLE = 160
MAX_CONTENT = 20_000
MAX_TAGS = 20
ALLOWED_STATUSES = frozenset({"draft", "active", "blocked", "completed", "archived"})
ALLOWED_SETTINGS = {
    "locale": {"en", "lv"},
    "theme": {"system", "light", "dark"},
    "default_chain": {"ethereum", "bitcoin", "polygon", "base", "arbitrum", "optimism"},
}
BOOL_SETTINGS = {"notifications"}
DEFAULT_SETTINGS = {
    "locale": "en",
    "theme": "system",
    "default_chain": "ethereum",
    "notifications": True,
}


class UserDataError(ValueError):
    """Invalid user-owned data or operation."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class UserDataStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _init_db(self):
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS research_records (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_research_owner_updated
                    ON research_records(user_id, updated_at DESC);
                CREATE TABLE IF NOT EXISTS user_settings (
                    user_id TEXT NOT NULL,
                    setting_key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(user_id, setting_key)
                );
                CREATE TABLE IF NOT EXISTS user_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    changed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_user_audit_owner
                    ON user_audit(user_id, id DESC);
            """)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _audit(db, user_id, action, entity_type, entity_id, metadata=None):
        db.execute(
            "INSERT INTO user_audit(user_id,action,entity_type,entity_id,metadata_json,changed_at) "
            "VALUES(?,?,?,?,?,?)",
            (user_id, action, entity_type, entity_id, _json(metadata or {}), _now()),
        )

    @staticmethod
    def _record(row):
        return {
            "id": row["id"], "title": row["title"], "content": row["content"],
            "tags": json.loads(row["tags_json"]), "status": row["status"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def list_records(self, user_id: str):
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM research_records WHERE user_id=? ORDER BY updated_at DESC",
                (user_id,),
            ).fetchall()
        return [self._record(r) for r in rows]

    def create_record(self, user_id: str, payload: dict):
        if not isinstance(payload, dict):
            raise UserDataError("record must be an object")
        title = payload.get("title")
        content = payload.get("content", "")
        tags = payload.get("tags", [])
        status = payload.get("status", "draft")
        if not isinstance(title, str) or not title.strip() or len(title.strip()) > MAX_TITLE:
            raise UserDataError("title must be 1–160 characters")
        if not isinstance(content, str) or len(content) > MAX_CONTENT:
            raise UserDataError("content must be a string up to 20000 characters")
        if not isinstance(tags, list) or len(tags) > MAX_TAGS or any(
            not isinstance(t, str) or len(t.strip()) > 40 for t in tags
        ):
            raise UserDataError("tags must be a list of up to 20 strings (40 chars each)")
        tags = list(dict.fromkeys(t.strip() for t in tags if t.strip()))
        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            raise UserDataError("invalid record status")
        rid, now = str(uuid.uuid4()), _now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO research_records VALUES(?,?,?,?,?,?,?,?)",
                (rid, user_id, title.strip(), content, _json(tags), status, now, now),
            )
            self._audit(db, user_id, "create", "research_record", rid,
                        {"status": status, "tag_count": len(tags)})
            row = db.execute("SELECT * FROM research_records WHERE id=?", (rid,)).fetchone()
        return self._record(row)

    def update_record(self, user_id: str, record_id: str, payload: dict):
        allowed = {"title", "content", "tags", "status"}
        if not isinstance(payload, dict) or not payload or set(payload) - allowed:
            raise UserDataError("provide one or more allowed fields: title, content, tags, status")
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM research_records WHERE id=? AND user_id=?",
                (record_id, user_id),
            ).fetchone()
            if row is None:
                return None
            current = self._record(row)
            merged = {**current, **payload}
            # Reuse creation validation without creating a row.
            title, content, tags, status = (
                merged["title"], merged["content"], merged["tags"], merged["status"]
            )
            if not isinstance(title, str) or not title.strip() or len(title.strip()) > MAX_TITLE:
                raise UserDataError("title must be 1–160 characters")
            if not isinstance(content, str) or len(content) > MAX_CONTENT:
                raise UserDataError("content must be a string up to 20000 characters")
            if not isinstance(tags, list) or len(tags) > MAX_TAGS or any(
                not isinstance(t, str) or len(t.strip()) > 40 for t in tags
            ):
                raise UserDataError("tags must be a list of up to 20 strings (40 chars each)")
            tags = list(dict.fromkeys(t.strip() for t in tags if t.strip()))
            if not isinstance(status, str) or status not in ALLOWED_STATUSES:
                raise UserDataError("invalid record status")
            now = _now()
            db.execute(
                "UPDATE research_records SET title=?,content=?,tags_json=?,status=?,updated_at=? "
                "WHERE id=? AND user_id=?",
                (title.strip(), content, _json(tags), status, now, record_id, user_id),
            )
            self._audit(db, user_id, "update", "research_record", record_id,
                        {"fields": sorted(payload.keys())})
            updated = db.execute(
                "SELECT * FROM research_records WHERE id=? AND user_id=?",
                (record_id, user_id),
            ).fetchone()
        return self._record(updated)

    def delete_record(self, user_id: str, record_id: str):
        with self._connect() as db:
            row = db.execute(
                "SELECT id FROM research_records WHERE id=? AND user_id=?",
                (record_id, user_id),
            ).fetchone()
            if row is None:
                return False
            db.execute(
                "DELETE FROM research_records WHERE id=? AND user_id=?",
                (record_id, user_id),
            )
            self._audit(db, user_id, "delete", "research_record", record_id)
        return True

    def get_settings(self, user_id: str):
        result = dict(DEFAULT_SETTINGS)
        with self._connect() as db:
            rows = db.execute(
                "SELECT setting_key,value_json FROM user_settings WHERE user_id=?",
                (user_id,),
            ).fetchall()
        for row in rows:
            result[row["setting_key"]] = json.loads(row["value_json"])
        return result

    def update_settings(self, user_id: str, payload: dict):
        if not isinstance(payload, dict) or not payload:
            raise UserDataError("settings must be a non-empty object")
        unknown = set(payload) - set(ALLOWED_SETTINGS) - BOOL_SETTINGS
        if unknown:
            raise UserDataError("unsupported or protected setting(s): " + ", ".join(sorted(unknown)))
        for key, value in payload.items():
            if key in BOOL_SETTINGS:
                if not isinstance(value, bool):
                    raise UserDataError(f"{key} must be a boolean")
            elif not isinstance(value, str) or value not in ALLOWED_SETTINGS[key]:
                raise UserDataError(f"invalid value for {key}")
        now = _now()
        with self._connect() as db:
            for key, value in payload.items():
                db.execute(
                    "INSERT INTO user_settings(user_id,setting_key,value_json,updated_at) "
                    "VALUES(?,?,?,?) ON CONFLICT(user_id,setting_key) DO UPDATE SET "
                    "value_json=excluded.value_json,updated_at=excluded.updated_at",
                    (user_id, key, _json(value), now),
                )
            self._audit(db, user_id, "update", "settings", "self",
                        {"keys": sorted(payload.keys())})
        return self.get_settings(user_id)

    def audit_log(self, user_id: str, limit: int = 100):
        limit = max(1, min(int(limit), 200))
        with self._connect() as db:
            rows = db.execute(
                "SELECT action,entity_type,entity_id,metadata_json,changed_at "
                "FROM user_audit WHERE user_id=? ORDER BY id DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [{
            "action": r["action"], "entity_type": r["entity_type"],
            "entity_id": r["entity_id"], "metadata": json.loads(r["metadata_json"]),
            "changed_at": r["changed_at"],
        } for r in rows]
