"""
PostgreSQL data access layer — connection management and CRUD for payments and blocked_users.

Reads DATABASE_URL from the environment:
    postgresql+psycopg2://user:pass@host/dbname
    postgresql+psycopg2://user:pass@/dbname?host=/cloudsql/PROJECT:REGION:INSTANCE  (Cloud Run)
"""

import logging
import os
from datetime import datetime

import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import fraud_detection as fd

logger = logging.getLogger(__name__)

# ── Column lists ────────────────────────────────────────────────────────────────

_PAYMENT_PK = "payment_id"
_PAYMENT_NON_PK_COLS = [
    "auth_codes", "card_type", "bank_name", "card_product_name", "card_segment",
    "card_credit_debit", "bin_country", "card_city", "card_country", "cvv_response",
    "card_email", "card_first_name", "card_ip", "card_ip_city", "card_region",
    "card_ip_zip", "card_last_name", "card_state", "card_street", "card_zip",
    "card_last4", "transaction_status", "transaction_type", "total_cents",
    "chargeback_decision", "customer_status", "customer_email", "customer_id",
    "error_message", "liability_owner", "card_token", "transaction_created_at",
]
_PAYMENT_ALL_COLS = [_PAYMENT_PK] + _PAYMENT_NON_PK_COLS

_BLOCKED_LIST_COLS = fd._BLOCKED_FIELDS + [
    "full_name",
    "all_card_ips", "all_card_emails", "all_card_tokens", "all_card_streets", "all_full_names",
    "reason_summary", "added_at", "source",
]
_BLOCKED_PK = "customer_id"
_BLOCKED_NON_PK_COLS = [c for c in _BLOCKED_LIST_COLS if c != _BLOCKED_PK]

# ── Engine (singleton) ──────────────────────────────────────────────────────────

_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is not None:
        return _engine
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set.\n"
            "Add it to your .env file:  DATABASE_URL=postgresql+psycopg2://..."
        )
    _engine = create_engine(url, pool_size=5, max_overflow=10, pool_pre_ping=True)
    return _engine


# ── Schema ─────────────────────────────────────────────────────────────────────

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS payments (
    payment_id             TEXT PRIMARY KEY,
    auth_codes             TEXT,
    card_type              TEXT,
    bank_name              TEXT,
    card_product_name      TEXT,
    card_segment           TEXT,
    card_credit_debit      TEXT,
    bin_country            TEXT,
    card_city              TEXT,
    card_country           TEXT,
    cvv_response           TEXT,
    card_email             TEXT,
    card_first_name        TEXT,
    card_ip                TEXT,
    card_ip_city           TEXT,
    card_region            TEXT,
    card_ip_zip            TEXT,
    card_last_name         TEXT,
    card_state             TEXT,
    card_street            TEXT,
    card_zip               TEXT,
    card_last4             TEXT,
    transaction_status     TEXT,
    transaction_type       TEXT,
    total_cents            INTEGER,
    chargeback_decision    TEXT,
    customer_status        TEXT,
    customer_email         TEXT,
    customer_id            TEXT,
    error_message          TEXT,
    liability_owner        TEXT,
    card_token             TEXT,
    transaction_created_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_payments_customer_id ON payments (customer_id);
CREATE INDEX IF NOT EXISTS idx_payments_created_at  ON payments (transaction_created_at);

CREATE TABLE IF NOT EXISTS blocked_users (
    customer_id      TEXT PRIMARY KEY,
    customer_email   TEXT,
    card_email       TEXT,
    card_first_name  TEXT,
    card_last_name   TEXT,
    card_ip          TEXT,
    card_city        TEXT,
    card_ip_city     TEXT,
    card_region      TEXT,
    card_ip_zip      TEXT,
    card_zip         TEXT,
    card_street      TEXT,
    card_token       TEXT,
    card_last4       TEXT,
    bin_country      TEXT,
    full_name        TEXT,
    all_card_ips     TEXT,
    all_card_emails  TEXT,
    all_card_tokens  TEXT,
    all_card_streets TEXT,
    all_full_names   TEXT,
    reason_summary   TEXT,
    added_at         TEXT,
    source           TEXT
);

CREATE TABLE IF NOT EXISTS verified_customers (
    customer_id         TEXT PRIMARY KEY,
    card_first_name     TEXT,
    card_last_name      TEXT,
    card_email          TEXT,
    note                TEXT,
    added_at            TEXT,
    added_by_payment_id TEXT
);
"""


def init_db() -> None:
    """Create tables and indexes if they do not exist. Safe to call multiple times."""
    with get_engine().begin() as conn:
        conn.execute(text(_INIT_SQL))


# ── Row normalization ───────────────────────────────────────────────────────────

def _to_int_or_none(v) -> int | None:
    if v is None or v is pd.NaT:
        return None
    if isinstance(v, float) and v != v:
        return None
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return None
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _to_ts_or_none(v) -> str | None:
    """Convert various timestamp representations to ISO string or None."""
    if v is None or v is pd.NaT:
        return None
    if isinstance(v, float) and v != v:
        return None
    if isinstance(v, pd.Timestamp):
        return None if pd.isna(v) else v.isoformat()
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return None
        # May be a raw Coinflow timestamp string — parse via fd.parse_timestamp
        parsed = fd.parse_timestamp(v)
        if parsed is None or parsed is pd.NaT:
            return None
        if isinstance(parsed, pd.Timestamp) and pd.isna(parsed):
            return None
        return parsed.isoformat()
    return None


def _to_str(v) -> str:
    """Normalize any value to a string, converting NaN/NaT/None to empty string."""
    if v is None or v is pd.NaT:
        return ""
    if isinstance(v, float) and v != v:
        return ""
    if hasattr(v, "item"):
        raw = v.item()
        return "" if raw is None else str(raw)
    return str(v)


def _make_payment_row(row: dict) -> dict:
    """Extract and normalize a payments row for SQL insertion."""
    out: dict = {}
    for col in _PAYMENT_ALL_COLS:
        v = row.get(col)
        if col == "total_cents":
            out[col] = _to_int_or_none(v)
        elif col == "transaction_created_at":
            out[col] = _to_ts_or_none(v)
        else:
            out[col] = _to_str(v)
    return out


def _make_blocked_row(entry: dict) -> dict:
    """Extract and normalize a blocked_users row for SQL insertion."""
    return {col: _to_str(entry.get(col, "")) for col in _BLOCKED_LIST_COLS}


# ── Prebuilt SQL ────────────────────────────────────────────────────────────────

_PAYMENT_UPSERT_SQL = (
    f"INSERT INTO payments ({', '.join(_PAYMENT_ALL_COLS)}) "
    f"VALUES ({', '.join(':' + c for c in _PAYMENT_ALL_COLS)}) "
    "ON CONFLICT (payment_id) DO UPDATE SET "
    + ", ".join(f"{c} = EXCLUDED.{c}" for c in _PAYMENT_NON_PK_COLS)
)

_BLOCKED_INSERT_SQL = (
    f"INSERT INTO blocked_users ({', '.join(_BLOCKED_LIST_COLS)}) "
    f"VALUES ({', '.join(':' + c for c in _BLOCKED_LIST_COLS)}) "
    "ON CONFLICT (customer_id) DO NOTHING"
)

_BLOCKED_UPSERT_SQL = (
    f"INSERT INTO blocked_users ({', '.join(_BLOCKED_LIST_COLS)}) "
    f"VALUES ({', '.join(':' + c for c in _BLOCKED_LIST_COLS)}) "
    "ON CONFLICT (customer_id) DO UPDATE SET "
    + ", ".join(f"{c} = EXCLUDED.{c}" for c in _BLOCKED_NON_PK_COLS)
)


# ── Payment CRUD ────────────────────────────────────────────────────────────────

def load_payments(since: datetime | None = None) -> pd.DataFrame:
    """Load payments from DB as a DataFrame ready for fraud_detection.score_all()."""
    if since is not None:
        stmt = text(
            "SELECT * FROM payments WHERE transaction_created_at >= :since"
        ).bindparams(since=since)
    else:
        stmt = text("SELECT * FROM payments")

    try:
        with get_engine().connect() as conn:
            df = pd.read_sql(stmt, conn)
    except Exception as exc:
        logger.warning("load_payments failed: %s", exc)
        return pd.DataFrame(columns=_PAYMENT_ALL_COLS)

    if df.empty:
        return df

    if "total_cents" in df.columns:
        df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)
    if "transaction_created_at" in df.columns:
        df["transaction_created_at"] = pd.to_datetime(
            df["transaction_created_at"], utc=True, errors="coerce"
        )

    # Ensure all columns expected by fraud_detection are present
    for col in fd.COLUMN_RENAME_MAP.values():
        if col not in df.columns:
            df[col] = ""

    return df


def upsert_payment(tx_df: pd.DataFrame) -> None:
    """Upsert a single-row DataFrame into the payments table."""
    if tx_df.empty:
        return
    row = tx_df.iloc[0].to_dict()
    pid = str(row.get("payment_id", "")).strip()
    if not pid:
        logger.warning("upsert_payment: skipping row with empty payment_id")
        return
    with get_engine().begin() as conn:
        conn.execute(text(_PAYMENT_UPSERT_SQL), _make_payment_row(row))


def upsert_payments_batch(df: pd.DataFrame) -> int:
    """Upsert a DataFrame of payments in chunks of 1000. Returns count of rows processed."""
    if df.empty:
        return 0
    total = 0
    chunk_size = 1000
    with get_engine().begin() as conn:
        for start in range(0, len(df), chunk_size):
            rows = [
                _make_payment_row(r)
                for _, r in df.iloc[start : start + chunk_size].iterrows()
                if str(r.get("payment_id", "")).strip()
            ]
            if rows:
                conn.execute(text(_PAYMENT_UPSERT_SQL), rows)
                total += len(rows)
    return total


# ── Blocked user CRUD ───────────────────────────────────────────────────────────

def load_blocked_users() -> pd.DataFrame:
    """Load all blocked users from DB as a DataFrame."""
    try:
        with get_engine().connect() as conn:
            df = pd.read_sql(text("SELECT * FROM blocked_users"), conn)
    except Exception as exc:
        logger.warning("load_blocked_users failed: %s", exc)
        return pd.DataFrame(columns=_BLOCKED_LIST_COLS)
    return df


def upsert_blocked_user(entry: dict) -> bool:
    """Insert a new blocked user. Returns True if inserted, False if already exists."""
    cid = str(entry.get("customer_id", "")).strip()
    if not cid:
        return False
    with get_engine().begin() as conn:
        result = conn.execute(text(_BLOCKED_INSERT_SQL), _make_blocked_row(entry))
    return result.rowcount > 0


def upsert_blocked_user_full(entry: dict) -> None:
    """Upsert a blocked user, overwriting all columns if customer_id already exists."""
    cid = str(entry.get("customer_id", "")).strip()
    if not cid:
        return
    with get_engine().begin() as conn:
        conn.execute(text(_BLOCKED_UPSERT_SQL), _make_blocked_row(entry))


def is_customer_blocked(customer_id: str) -> bool:
    """Return True if customer_id exists in blocked_users."""
    cid = str(customer_id).strip()
    if not cid:
        return False
    with get_engine().connect() as conn:
        result = conn.execute(
            text("SELECT 1 FROM blocked_users WHERE customer_id = :cid LIMIT 1"),
            {"cid": cid},
        )
        return result.fetchone() is not None


# ── Verified customer CRUD ──────────────────────────────────────────────────────

_VERIFIED_COLS = [
    "customer_id", "card_first_name", "card_last_name", "card_email",
    "note", "added_at", "added_by_payment_id",
]

_VERIFIED_INSERT_SQL = (
    f"INSERT INTO verified_customers ({', '.join(_VERIFIED_COLS)}) "
    f"VALUES ({', '.join(':' + c for c in _VERIFIED_COLS)}) "
    "ON CONFLICT (customer_id) DO NOTHING"
)


def add_verified_customer(entry: dict) -> bool:
    """Insert a verified customer. Returns True if inserted, False if already exists."""
    cid = str(entry.get("customer_id", "")).strip()
    if not cid:
        return False
    row = {col: _to_str(entry.get(col, "")) for col in _VERIFIED_COLS}
    with get_engine().begin() as conn:
        result = conn.execute(text(_VERIFIED_INSERT_SQL), row)
    return result.rowcount > 0


def load_verified_customer_ids() -> set:
    """Return a set of lowercased customer_ids from verified_customers."""
    try:
        with get_engine().connect() as conn:
            result = conn.execute(text("SELECT customer_id FROM verified_customers"))
            return {str(row[0]).strip().lower() for row in result if row[0]}
    except Exception as exc:
        logger.warning("load_verified_customer_ids failed: %s", exc)
        return set()
