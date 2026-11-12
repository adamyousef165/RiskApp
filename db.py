"""
Local storage (SQLite): user accounts and saved assessments.

Passwords are never stored in plain text - they are hashed with PBKDF2-SHA256
and a random salt. This is a demo-grade login for a local prototype.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "riskapp.db"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ITERATIONS = 200_000


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                org_name      TEXT NOT NULL,
                business_type TEXT NOT NULL,
                salt          BLOB NOT NULL,
                pw_hash       BLOB NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                label      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                cve_id      TEXT NOT NULL,
                risk_level  TEXT NOT NULL,
                risk_score  REAL NOT NULL,
                input_json  TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
        """)


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)


# ---------------------------------------------------------------- accounts --
def create_user(email: str, password: str, org_name: str, business_type: str) -> str | None:
    """Returns an error message, or None on success."""
    email = email.strip().lower()
    if not EMAIL_PATTERN.match(email):
        return "Enter a valid email address."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not org_name.strip():
        return "Enter your organization name."
    salt = os.urandom(16)
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                (email, org_name.strip(), business_type, salt, _hash(password, salt),
                 datetime.now().isoformat(timespec="seconds")),
            )
    except sqlite3.IntegrityError:
        return "An account with this email already exists."
    return None


def check_login(email: str, password: str) -> dict | None:
    """Returns the user (without password data) if the login is correct."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?",
                           (email.strip().lower(),)).fetchone()
    if row is None:
        _hash(password, b"0" * 16)  # same work either way, so timing reveals nothing
        return None
    if not hmac.compare_digest(_hash(password, row["salt"]), row["pw_hash"]):
        return None
    return {"email": row["email"], "org_name": row["org_name"],
            "business_type": row["business_type"]}


# ------------------------------------------------------------- assessments --
def save_run(email: str, label: str, rows: list[tuple[dict, dict]]) -> int:
    """rows = [(record, result), ...]. Returns the new run id."""
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs (email, created_at, label) VALUES (?, ?, ?)",
            (email, datetime.now().isoformat(timespec="seconds"), label),
        )
        run_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO assessments (run_id, cve_id, risk_level, risk_score, input_json, result_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [(run_id, rec["cve_id"], res["risk_level"], res["risk_score"],
              json.dumps(rec), json.dumps(res)) for rec, res in rows],
        )
    return run_id


def add_to_run(email: str, run_id: int, rows: list[tuple[dict, dict]]) -> bool:
    """Append rows to an existing run. Returns False if the run isn't this user's."""
    with _connect() as conn:
        owner = conn.execute("SELECT email FROM runs WHERE id = ?", (run_id,)).fetchone()
        if owner is None or owner["email"] != email:
            return False
        conn.executemany(
            "INSERT INTO assessments (run_id, cve_id, risk_level, risk_score, input_json, result_json)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [(run_id, rec["cve_id"], res["risk_level"], res["risk_score"],
              json.dumps(rec), json.dumps(res)) for rec, res in rows],
        )
    return True


def load_all(email: str) -> list[tuple[dict, dict, int]]:
    """Every vulnerability this user has ever assessed, across all runs."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT a.input_json, a.result_json, a.run_id FROM assessments a
            JOIN runs r ON r.id = a.run_id
            WHERE r.email = ? ORDER BY a.id
        """, (email,)).fetchall()
    return [(json.loads(r["input_json"]), json.loads(r["result_json"]), r["run_id"]) for r in rows]


def list_runs(email: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("""
            SELECT r.id, r.created_at, r.label, COUNT(a.id) AS n,
                   SUM(a.risk_level = 'Critical') AS critical
            FROM runs r LEFT JOIN assessments a ON a.run_id = r.id
            WHERE r.email = ? GROUP BY r.id ORDER BY r.id DESC
        """, (email,)).fetchall()
    return [dict(r) for r in rows]


def load_run(email: str, run_id: int) -> list[tuple[dict, dict, int]]:
    """Only returns the run if it belongs to this user."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT a.input_json, a.result_json, a.run_id FROM assessments a
            JOIN runs r ON r.id = a.run_id
            WHERE a.run_id = ? AND r.email = ? ORDER BY a.id
        """, (run_id, email)).fetchall()
    return [(json.loads(r["input_json"]), json.loads(r["result_json"]), r["run_id"]) for r in rows]


def delete_run(email: str, run_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM runs WHERE id = ? AND email = ?", (run_id, email))
