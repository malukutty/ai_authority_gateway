import os
import sqlite3
import time
import hashlib
from typing import Optional, Dict, Any, Tuple

DB_PATH = os.getenv("KEYSTORE_DB_PATH", "keystore.db")

def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = _conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_hash TEXT PRIMARY KEY,
                key_prefix TEXT NOT NULL,
                status TEXT NOT NULL,
                allowed_envs TEXT NOT NULL,
                requests_per_day INTEGER NOT NULL,
                recipients_per_day INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                notes TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)")
        conn.commit()
    finally:
        conn.close()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def insert_key(
    raw_key: str,
    key_prefix: str,
    allowed_envs: str,
    requests_per_day: int,
    recipients_per_day: int,
    notes: str = ""
) -> Dict[str, Any]:
    key_hash = sha256_hex(raw_key)
    now = int(time.time())
    conn = _conn()
    try:
        conn.execute(
            """
            INSERT INTO api_keys
            (key_hash, key_prefix, status, allowed_envs, requests_per_day, recipients_per_day, created_at, notes)
            VALUES (?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
            """,
            (key_hash, key_prefix, allowed_envs, requests_per_day, recipients_per_day, now, notes),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "api_key": raw_key,
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "status": "ACTIVE",
        "allowed_envs": allowed_envs,
        "requests_per_day": requests_per_day,
        "recipients_per_day": recipients_per_day,
        "created_at": now,
    }

def get_key_by_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1",
            (key_hash,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def revoke_key(key_hash: str) -> bool:
    now = int(time.time())
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE api_keys SET status='REVOKED', revoked_at=? WHERE key_hash=? AND status='ACTIVE'",
            (now, key_hash),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

def env_allowed(allowed_envs: str, env: str) -> bool:
    allowed = [e.strip().lower() for e in (allowed_envs or "").split(",") if e.strip()]
    return env.strip().lower() in allowed
