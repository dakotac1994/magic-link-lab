"""SQLite-backed registry of issued magic links.

Table `magic_links` holds one row per issued link:
- `token_hash`  -- SHA-256 of the token (UNIQUE); the raw token is never stored
- `identifier`  -- normalized email or phone the link was sent to
- `channel`     -- "email" | "sms"
- `created_at` / `expires_at` -- epoch seconds; links die after the TTL
- `consumed_at` -- set on first successful verify; enforces single-use
- `ip`          -- requesting IP, for abuse forensics

Key operations are single atomic SQL statements so concurrent verifies of the
same link cannot both succeed (the consume UPDATE only matches unconsumed,
unexpired rows).
"""

import sqlite3
import threading
import time

from .tokens import DEFAULT_TTL_SECONDS, hash_token

_SCHEMA = """
CREATE TABLE IF NOT EXISTS magic_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,
    identifier  TEXT NOT NULL,
    channel     TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    consumed_at REAL,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS idx_magic_links_identifier
    ON magic_links (identifier);
CREATE INDEX IF NOT EXISTS idx_magic_links_expires
    ON magic_links (expires_at);
"""


class MagicLinkStore:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- issuance ---------------------------------------------------------
    def issue(self, token: str, identifier: str, channel: str,
              ip: str | None = None, ttl: int = DEFAULT_TTL_SECONDS,
              now: float | None = None) -> dict:
        """Record a new magic link, revoking any prior live links for the
        same identifier (only the newest link works -- limits blast radius)."""
        now = time.time() if now is None else now
        identifier = identifier.strip().lower()
        with self._lock:
            self._conn.execute(
                "UPDATE magic_links SET consumed_at = ? "
                "WHERE identifier = ? AND consumed_at IS NULL AND expires_at > ?",
                (now, identifier, now),
            )
            self._conn.execute(
                "INSERT INTO magic_links "
                "(token_hash, identifier, channel, created_at, expires_at, ip)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (hash_token(token), identifier, channel,
                 now, now + ttl, ip),
            )
            self._conn.commit()
        return {"identifier": identifier, "channel": channel,
                "expires_at": now + ttl}

    # -- verification -----------------------------------------------------
    def lookup(self, token: str) -> dict | None:
        """Fetch a link row by presented token (hashes first)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM magic_links WHERE token_hash = ?",
                (hash_token(token),),
            ).fetchone()
        return dict(row) if row else None

    def consume(self, token: str, now: float | None = None) -> dict | None:
        """Atomically consume a link. Returns the row on success, None when
        the token is unknown, expired, or already used (replay attempt)."""
        now = time.time() if now is None else now
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM magic_links "
                "WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
                (hash_token(token), now),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE magic_links SET consumed_at = ? WHERE token_hash = ?",
                (now, hash_token(token)),
            )
            self._conn.commit()
            return dict(row)

    # -- housekeeping -----------------------------------------------------
    def purge_expired(self, now: float | None = None) -> int:
        """Delete dead rows (expired or consumed). Returns rows removed."""
        now = time.time() if now is None else now
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM magic_links "
                "WHERE expires_at <= ? OR consumed_at IS NOT NULL",
                (now,),
            )
            self._conn.commit()
            return cur.rowcount

    def live_count(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM magic_links "
                "WHERE consumed_at IS NULL AND expires_at > ?",
                (now,),
            ).fetchone()
        return row["n"]
