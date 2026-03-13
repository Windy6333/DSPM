from __future__ import annotations

"""
storage.py — SQLite persistence layer.

Tables:

upload_events
  filepath, username, user_email, upload_time

incidents
  incident_id, filepath, username, user_email,
  detected_at, notified, resolved

incident_dlp
  incident_id, data_type, sensitivity, occurrence_count
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


# ──────────────────────────────────────────────
# DB Initialization
# ──────────────────────────────────────────────

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
            incident_id TEXT PRIMARY KEY,
            filepath    TEXT NOT NULL,
            username    TEXT NOT NULL,
            user_email  TEXT,
            detected_at TEXT NOT NULL,
            notified    INTEGER NOT NULL DEFAULT 0,
            resolved    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS incident_dlp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            data_type TEXT,
            sensitivity TEXT,
            occurrence_count INTEGER,
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_filepath
        ON incidents(filepath);

        CREATE INDEX IF NOT EXISTS idx_dlp_incident
        ON incident_dlp(incident_id);

        """)

    logger.info("DB ready: %s", Config.DB_PATH)


# ───────�──────────────────────────────────────
# Upload Events
# ──────────────────────────────────────────────

def save_upload_event(filepath: str, username: str, user_email: str, upload_time: str):

    with _conn() as c:

        c.execute(
            "INSERT OR REPLACE INTO upload_events "
            "(filepath, username, user_email, upload_time) VALUES (?,?,?,?)",
            (filepath, username, user_email, upload_time)
        )


def get_upload_event(filepath: str):

    with _conn() as c:

        row = c.execute(
            "SELECT * FROM upload_events WHERE filepath = ?",
            (filepath,)
        ).fetchone()

        return dict(row) if row else None


# ──────────────────────────────────────────────
# Incidents
# ──────────────────────────────────────────────

def get_incident(filepath: str):

    with _conn() as c:

        row = c.execute(
            "SELECT * FROM incidents WHERE filepath = ? ORDER BY detected_at DESC LIMIT 1",
            (filepath,)
        ).fetchone()

        return dict(row) if row else None


def create_incident(
    filepath: str,
    username: str,
    user_email: str,
    detected_at: str,
    dlp_profiles: list
):

    incident_id = str(uuid.uuid4())

    with _conn() as c:

        c.execute(
            "INSERT INTO incidents "
            "(incident_id, filepath, username, user_email, detected_at, notified, resolved) "
            "VALUES (?,?,?,?,?,0,0)",
            (incident_id, filepath, username, user_email, detected_at)
        )

        for p in dlp_profiles:

            c.execute(
                "INSERT INTO incident_dlp "
                "(incident_id, data_type, sensitivity, occurrence_count) "
                "VALUES (?,?,?,?)",
                (
                    incident_id,
                    p.get("type"),
                    p.get("sensitivity"),
                    p.get("count")
                )
            )

    logger.info(
        "Incident created: %s | %s | uploader: %s",
        incident_id,
        filepath,
        username
    )

    return incident_id


def get_incident_dlp(incident_id: str):

    with _conn() as c:

        rows = c.execute(
            "SELECT data_type, sensitivity, occurrence_count "
            "FROM incident_dlp WHERE incident_id = ?",
            (incident_id,)
        ).fetchall()

        return [dict(r) for r in rows]


def mark_notified(incident_id: str):

    with _conn() as c:

        c.execute(
            "UPDATE incidents SET notified = 1 WHERE incident_id = ?",
            (incident_id,)
        )


# ──────────────────────────────────────────────
# Stats
# ──────────────────────────────────────────────

def get_stats():

    with _conn() as c:

        return {

            "upload_events":
                c.execute("SELECT COUNT(*) FROM upload_events").fetchone()[0],

            "total_incidents":
                c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],

            "notified_incidents":
                c.execute("SELECT COUNT(*) FROM incidents WHERE notified = 1").fetchone()[0],

            "unresolved_incidents":
                c.execute("SELECT COUNT(*) FROM incidents WHERE resolved = 0").fetchone()[0],
        }
