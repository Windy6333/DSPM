"""
storage.py — SQLite persistence layer.

Tables:
  upload_events  (filepath, username, user_email, upload_time)
                  user_email may be comma-separated if uploader has multiple emails

  incidents      (incident_id, filepath, username, user_email,
                  detected_at, notified, resolved)
"""

import sqlite3
import uuid
import logging
from contextlib import contextmanager
from config import Config

logger = logging.getLogger(__name__)


@contextmanager
def _conn():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS upload_events (
                filepath    TEXT PRIMARY KEY,
                username    TEXT NOT NULL,
                user_email  TEXT,
                upload_time TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id  TEXT PRIMARY KEY,
                filepath     TEXT NOT NULL,
                username     TEXT NOT NULL,
                user_email   TEXT,
                detected_at  TEXT NOT NULL,
                notified     INTEGER NOT NULL DEFAULT 0,
                resolved     INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_filepath
                ON incidents(filepath);
        """)
    logger.info("DB ready: %s", Config.DB_PATH)


# ── upload events ──────────────────────────────────────────────────────────────

def save_upload_event(filepath: str, username: str, user_email: str, upload_time: str):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO upload_events "
            "(filepath, username, user_email, upload_time) VALUES (?,?,?,?)",
            (filepath, username, user_email, upload_time)
        )


def get_upload_event(filepath: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM upload_events WHERE filepath = ?", (filepath,)
        ).fetchone()
        return dict(row) if row else None


# ── incidents ──────────────────────────────────────────────────────────────────

def get_incident(filepath: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM incidents WHERE filepath = ? ORDER BY detected_at DESC LIMIT 1",
            (filepath,)
        ).fetchone()
        return dict(row) if row else None


def create_incident(
    filepath:    str,
    username:    str,
    user_email:  str,
    detected_at: str,
) -> str:
    incident_id = str(uuid.uuid4())
    with _conn() as c:
        c.execute(
            "INSERT INTO incidents "
            "(incident_id, filepath, username, user_email, detected_at, notified, resolved) "
            "VALUES (?,?,?,?,?,0,0)",
            (incident_id, filepath, username, user_email, detected_at)
        )
    logger.info("Incident created: %s | %s | uploader: %s", incident_id, filepath, username)
    return incident_id


def mark_notified(incident_id: str):
    with _conn() as c:
        c.execute(
            "UPDATE incidents SET notified = 1 WHERE incident_id = ?",
            (incident_id,)
        )


# ── stats ──────────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    with _conn() as c:
        return {
            "upload_events":        c.execute("SELECT COUNT(*) FROM upload_events").fetchone()[0],
            "total_incidents":      c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            "notified_incidents":   c.execute("SELECT COUNT(*) FROM incidents WHERE notified = 1").fetchone()[0],
            "unresolved_incidents": c.execute("SELECT COUNT(*) FROM incidents WHERE resolved = 0").fetchone()[0],
        }
