"""
x402 Payment Middleware — Rate Limiting + API Key Gate
======================================================

Free tier:  SCAN_FREE_TIER scans/day per client IP/session (default: 1)
Paid tier:  Unlimited scans with valid API key in X-API-Key header
Payment:    HTTP 402 returned when free tier exhausted — $SCAN_PRICE_USD USDC on Base

API keys are UUIDs stored in SQLite, granted after BTC payment confirmation
(follows the Blockonomics pattern from agent-guardrail/billing.py).

Graceful disable: if MCP_BILLING_ENABLED=false, all scans pass through (default: enabled).
"""

import hashlib
import logging
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ── env config ────────────────────────────────────────────────────────────────
SCAN_FREE_TIER = int(os.environ.get("SCAN_FREE_TIER", "1"))
SCAN_PRICE_USD = os.environ.get("SCAN_PRICE_USD", "0.25")
SCAN_WALLET_ADDRESS = os.environ.get("SCAN_WALLET_ADDRESS", "")
MCP_BILLING_DB = os.environ.get("MCP_BILLING_DB", "/opt/mcp-audit/billing.db")

# ── schema ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_usage (
    client_id   TEXT NOT NULL,          -- hash of IP or X-Session-Id
    scan_date   TEXT NOT NULL,          -- YYYY-MM-DD UTC
    scan_count  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (client_id, scan_date)
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,       -- UUID
    key_hash    TEXT NOT NULL UNIQUE,   -- SHA-256 of raw key (raw never stored)
    label       TEXT,
    created_at  TEXT NOT NULL,
    last_used   TEXT,
    active      INTEGER NOT NULL DEFAULT 1
);
"""


class BillingGate:
    """Rate limiting + API key gate for MCP security_scan tool."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or MCP_BILLING_DB

    @property
    def enabled(self) -> bool:
        flag = os.environ.get("MCP_BILLING_ENABLED", "true").lower()
        return flag not in ("false", "0", "no")

    # ── DB helpers ─────────────────────────────────────────────────────────────

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return conn

    # ── API key validation ─────────────────────────────────────────────────────

    def validate_api_key(self, raw_key: str) -> bool:
        """Return True if the raw key is active."""
        if not raw_key:
            return False
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT key_id FROM api_keys WHERE key_hash = ? AND active = 1",
                (key_hash,),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE api_keys SET last_used = ? WHERE key_id = ?",
                    (datetime.now(timezone.utc).isoformat(), row["key_id"]),
                )
                conn.commit()
                return True
            return False
        finally:
            conn.close()

    def create_api_key(self, label: str = "") -> dict:
        """Generate a new API key. Returns {key_id, raw_key}. Raw key shown once."""
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        conn = self._db()
        try:
            conn.execute(
                "INSERT INTO api_keys (key_id, key_hash, label, created_at, active) "
                "VALUES (?, ?, ?, ?, 1)",
                (key_id, key_hash, label, now),
            )
            conn.commit()
        finally:
            conn.close()

        logger.info("API key created: %s (label=%r)", key_id, label)
        return {"key_id": key_id, "raw_key": raw_key}

    def revoke_api_key(self, key_id: str) -> bool:
        """Deactivate an API key. Returns True if found."""
        conn = self._db()
        try:
            cur = conn.execute(
                "UPDATE api_keys SET active = 0 WHERE key_id = ?", (key_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ── Free tier tracking ─────────────────────────────────────────────────────

    def _check_and_increment(self, client_id: str) -> Tuple[bool, int]:
        """Atomic check + increment. Returns (allowed, scans_used_today)."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc).isoformat()

        conn = self._db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT scan_count FROM scan_usage WHERE client_id = ? AND scan_date = ?",
                (client_id, today),
            ).fetchone()

            if row is None:
                conn.execute(
                    "INSERT INTO scan_usage (client_id, scan_date, scan_count, updated_at) "
                    "VALUES (?, ?, 1, ?)",
                    (client_id, today, now),
                )
                conn.commit()
                return True, 1

            count = row["scan_count"]
            if count >= SCAN_FREE_TIER:
                conn.rollback()
                return False, count

            conn.execute(
                "UPDATE scan_usage SET scan_count = scan_count + 1, updated_at = ? "
                "WHERE client_id = ? AND scan_date = ?",
                (now, client_id, today),
            )
            conn.commit()
            return True, count + 1
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Main gate ──────────────────────────────────────────────────────────────

    def check(self, api_key: str = "", client_ip: str = "", session_id: str = "") -> Tuple[bool, str]:
        """Gate check. Returns (allowed, reason).

        Reason values:
          billing_disabled  — billing is off, pass through
          api_key_valid     — valid API key, unlimited
          api_key_invalid   — X-API-Key present but wrong
          free_tier         — within free quota
          limit_exceeded    — free tier exhausted, no API key
        """
        if not self.enabled:
            return True, "billing_disabled"

        # API key takes priority
        if api_key:
            if self.validate_api_key(api_key):
                return True, "api_key_valid"
            return False, "api_key_invalid"

        # Derive stable client identity: prefer session_id, fall back to IP
        raw_id = session_id or client_ip or "unknown"
        client_id = hashlib.sha256(raw_id.encode()).hexdigest()[:32]

        allowed, count = self._check_and_increment(client_id)
        if allowed:
            return True, "free_tier"
        return False, "limit_exceeded"

    # ── 402 payload ────────────────────────────────────────────────────────────

    def payment_required_payload(self) -> dict:
        """Standard x402-style HTTP 402 body."""
        return {
            "error": "payment_required",
            "http_status": 402,
            "message": (
                f"Free tier exhausted ({SCAN_FREE_TIER} scan/day). "
                f"Add X-API-Key header with a paid key, or pay ${SCAN_PRICE_USD} USDC to scan."
            ),
            "free_tier": {
                "scans_per_day": SCAN_FREE_TIER,
                "resets": "00:00 UTC",
            },
            "payment": {
                "price": SCAN_PRICE_USD,
                "currency": "USDC",
                "network": "base",
                "address": SCAN_WALLET_ADDRESS,
                "message": f"Pay ${SCAN_PRICE_USD} USDC on Base to https://eren-solutions.com/audit/pay",
            },
            "api_key_info": "Contact https://eren-solutions.com/audit/buy for an API key",
        }
