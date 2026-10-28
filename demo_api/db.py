"""SQLite storage for the demo API (users and private records)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

from demo_api import settings
from demo_api.security import hash_password

_lock = threading.Lock()

SEED_USERS = [
    ("alice", "Alice@123", "user", "Alice Fernandes"),
    ("bob", "Bob@123", "user", "Bob Mathew"),
    ("mallory", "Mallory@123", "user", "Mallory Quinn"),
    ("admin", "Admin@123", "admin", "Platform Administrator"),
]
SEED_RECORDS = [
    (101, "alice", "Medical summary", "Blood group O+. Allergic to penicillin."),
    (102, "alice", "Bank details", "Account ending 4821, IFSC HDFC0001234."),
    (201, "bob", "Tax return 2025", "Gross income INR 18,40,000."),
    (202, "bob", "Passport", "Passport number Z1234567, expires 2031."),
    (301, "mallory", "Notes", "Shopping list."),
]


@contextmanager
def connect():
    settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(reset: bool = False) -> None:
    with _lock, connect() as conn:
        if reset:
            conn.executescript("DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS users;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                full_name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL REFERENCES users(username),
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                [(u, hash_password(p), r, n) for u, p, r, n in SEED_USERS],
            )
            conn.executemany("INSERT INTO records (id, owner, title, content) VALUES (?, ?, ?, ?)", SEED_RECORDS)


def get_user(username: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_record(record_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
        return dict(row) if row else None


def list_records(owner: str) -> list[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM records WHERE owner = ? ORDER BY id", (owner,))]


def create_record(owner: str, title: str, content: str) -> dict:
    with _lock, connect() as conn:
        cur = conn.execute("INSERT INTO records (owner, title, content) VALUES (?, ?, ?)", (owner, title, content))
        rid = cur.lastrowid
    return get_record(rid)  # type: ignore[arg-type]


def update_record(record_id: int, title: str, content: str) -> dict | None:
    with _lock, connect() as conn:
        conn.execute(
            "UPDATE records SET title = ?, content = ?, updated_at = datetime('now') WHERE id = ?",
            (title, content, record_id),
        )
    return get_record(record_id)
