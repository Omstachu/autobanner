"""
Webhook server — listens for Coinflow payment events and scores each transaction.

On each webhook:
  1. Fetch the full payment from the Coinflow API (the webhook payload is sparse).
  2. Score it using the same fraud detection rule engine as fetch_and_score.py.
  3. Print results to console; print INSTANT BAN if high-severity rules fire.
  4. Auto-append to blocked_users.csv if TOKEN_BLOCKED or EMAIL_BLOCKED fires.

Transaction history is maintained in-memory (loaded from the payments CSV on startup)
and appended to live_payments.csv for crash recovery.

Usage:
    python webhook_server.py              # port 5000
    python webhook_server.py --port 8080

Required .env:
    COINFLOW_API_KEY=...

Optional .env:
    COINFLOW_API_URL=https://api.coinflow.cash/api
    COINFLOW_VALIDATION_KEY=...    # from Coinflow dashboard → Developers → Webhooks
"""

import argparse
import contextlib
import hashlib
import hmac
import io
import os
import sys
import threading
import time
from datetime import datetime, timedelta, UTC
from zoneinfo import ZoneInfo

import pandas as pd
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request

import db
import download_payments as dl
import fraud_detection as fd

load_dotenv()

# ── Terminal colors ────────────────────────────────────────────────────────────
# Set to "catppuccin" for Catppuccin Mocha palette, or "default" for standard ANSI colors.

# Disable colors in Cloud Run (K_SERVICE is set by the runtime; ANSI codes pollute Cloud Logging)
COLOR_THEME = "none" if os.getenv("K_SERVICE") else "catppuccin"

def _tc(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"

_THEMES: dict = {
    "default": {
        "red":    "\033[91m",
        "yellow": "\033[93m",
        "cyan":   "\033[96m",
        "green":  "\033[92m",
        "blue":   "\033[94m",
        "mauve":  "\033[95m",
        "bold":   "\033[1m",
        "dim":    "\033[2m",
        "reset":  "\033[0m",
    },
    "catppuccin": {           # Catppuccin Mocha
        "red":    _tc(243, 139, 168),  # red      #f38ba8
        "yellow": _tc(249, 226, 175),  # yellow   #f9e2af
        "cyan":   _tc(137, 220, 235),  # sky      #89dceb
        "green":  _tc(166, 227, 161),  # green    #a6e3a1
        "blue":   _tc(137, 180, 250),  # blue     #89b4fa
        "mauve":  _tc(203, 166, 247),  # mauve    #cba6f7
        "bold":   "\033[1m",
        "dim":    _tc(166, 173, 200),  # subtext1 #a6adc8
        "reset":  "\033[0m",
    },
}

_THEMES["none"] = {k: "" for k in _THEMES["default"]}
_C = _THEMES.get(COLOR_THEME, _THEMES["default"])

def _risk_color(level: str) -> str:
    return {"HIGH": _C["red"], "MEDIUM": _C["yellow"], "LOW": _C["cyan"], "FLAG_LOW": _C["dim"]}.get(level, "")

# ── Configuration ──────────────────────────────────────────────────────────────

COINFLOW_API_URL         = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY         = os.getenv("COINFLOW_API_KEY", "")
COINFLOW_VALIDATION_KEY  = os.getenv("COINFLOW_VALIDATION_KEY", "")
WEBHOOK_PATH_TOKEN       = os.getenv("WEBHOOK_PATH_TOKEN", "")

BLOCKED_LIST_PATH = "blocked_users.csv"  # kept for log messages only

# Rules that trigger auto-append to blocked_users.csv (not IP_BLOCKED — shared IPs)
INSTANT_BLOCK_RULES = {
    "TOKEN_BLOCKED", "EMAIL_BLOCKED", "AUTH_CODES_INSTANT",
    "FRAUD_CODE_ZERO_ACCEPT", "MULTI_NAME_LOW_ACCEPT", "IP_FRAUD_CODE_ZERO_ACCEPT",
}

HANDLED_EVENT_TYPES = {"Settled", "Card Payment Authorized", "Card Payment Declined"}

# ── Server state ───────────────────────────────────────────────────────────────

_lock = threading.Lock()
_history_df:  pd.DataFrame = pd.DataFrame()
_blocked_df:  pd.DataFrame = pd.DataFrame()
_female_names: set         = set()
_name_freq:    dict        = {}
_verified_customer_ids: set = set()

# ── Shared helpers (mirrored from fetch_and_score.py — no cross-import) ───────

_BLOCKED_LIST_COLS = fd._BLOCKED_FIELDS + [
    "full_name",
    "all_card_ips", "all_card_emails", "all_card_tokens", "all_card_streets", "all_full_names",
    "reason_summary", "added_at", "source",
]


def _flatten(obj: dict, prefix: str = "", sep: str = ".") -> dict:
    items: dict = {}
    for k, v in obj.items():
        key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            items.update(_flatten(v, key, sep))
        elif isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            items[key] = ",".join(v)
        else:
            items[key] = v
    return items


def _norm_id(s) -> str:
    return str(s).replace("-", "").lower().strip()


_EASTERN = ZoneInfo("America/New_York")


def _ts() -> str:
    return datetime.now(_EASTERN).strftime("%Y-%m-%d %H:%M:%S")


def _get_val(row, col: str, default: str = "") -> str:
    v = row.get(col, default)
    return str(v).strip() if v and not (isinstance(v, float) and pd.isna(v)) else default


def _format_amount(row) -> str:
    cents = row.get("total_cents", 0)
    try:
        return f"${int(cents) / 100:.2f}"
    except (ValueError, TypeError):
        return ""


def _customer_url(customer_id: str) -> str:
    if fd.CUSTOMER_URL_TEMPLATE and customer_id:
        return fd.CUSTOMER_URL_TEMPLATE.format(customer_id)
    return ""


def _matched_blocked_url(result_row) -> tuple[str, str]:
    threshold = fd.FUZZY_MATCH_THRESHOLD
    r03_score = int(result_row.get("_r03_score", 0) or 0)
    r06_score = int(result_row.get("_r06_score", 0) or 0)
    if r03_score >= threshold:
        cid = _get_val(result_row, "_r03_matched_cid")
        if cid:
            return cid, _customer_url(cid)
    if r06_score >= threshold:
        cid = _get_val(result_row, "_r06_matched_cid")
        if cid:
            return cid, _customer_url(cid)
    return "", ""


def _match_explanation(result_row, tx_row) -> str:
    threshold = fd.FUZZY_MATCH_THRESHOLD
    parts = []
    r03 = int(result_row.get("_r03_score", 0) or 0)
    r06 = int(result_row.get("_r06_score", 0) or 0)
    if r03 >= threshold:
        card_email = _get_val(tx_row, "card_email")
        matched    = _get_val(result_row, "_r03_matched_email")
        parts.append(f"Email {r03}% match ({card_email} ~ {matched})")
    if r06 >= threshold:
        first = _get_val(tx_row, "card_first_name")
        last  = _get_val(tx_row, "card_last_name")
        name  = f"{first} {last}".strip()
        matched = _get_val(result_row, "_r06_matched_name")
        parts.append(f"Name {r06}% match ({name} ~ {matched})")
    return " | ".join(parts)


def _print_result(
    event_type: str,
    tx_df: pd.DataFrame,
    result_df: pd.DataFrame,
    success_rate: int | None = None,
    txn_count: int = 0,
    is_verified: bool = False,
) -> None:
    W    = 70
    SEP  = "═" * W
    LINE = "─" * W
    R    = _C["reset"]

    tx_row      = tx_df.iloc[0]
    payment_id  = _get_val(tx_row, "payment_id")
    customer_id = _get_val(tx_row, "customer_id")
    amount      = _format_amount(tx_row)
    status      = _get_val(tx_row, "transaction_status")
    cust_url    = _customer_url(customer_id)
    first       = str(tx_row.get("card_first_name") or "").strip().title()
    last        = str(tx_row.get("card_last_name")  or "").strip().title()
    card_name   = f"{first} {last}".strip()

    VERIFIED_BADGE = f" {_C['mauve']}[verified]{R}" if is_verified else ""

    def _sr_line() -> str:
        if success_rate is None or txn_count == 0:
            return ""
        color = _C["green"] if success_rate >= 90 else (_C["blue"] if success_rate >= 70 else _C["red"])
        return f"  Success rate: {color}{success_rate}%{R} ({txn_count} txn{'s' if txn_count != 1 else ''})"

    print(f"\n{_C['green']}{SEP}{R}")
    print(f"[{event_type}]")

    if result_df.empty:
        amt_str = f"  |  Amount: {amount}" if amount else ""
        if card_name:
            print(f"{_C['bold']}{card_name}{R}{VERIFIED_BADGE}  |  {customer_id}{amt_str}")
        else:
            print(f"Payment: {payment_id}  |  Customer: {customer_id}{VERIFIED_BADGE}{amt_str}")
        if status:
            print(f"  [{status}]")
        sr = _sr_line()
        if sr:
            print(sr)
        print(f"{_C['green']}✓ No fraud signals detected{R}")
        print(f"{_C['green']}{SEP}{R}")
        return

    result_row = result_df.iloc[0]
    risk_level = _get_val(result_row, "risk_level", "—")
    risk_score   = _get_val(result_row, "risk_score", "0")
    flag_count   = _get_val(result_row, "flag_count", "0")
    reason_sum   = _get_val(result_row, "reason_summary", "")
    rules_trig   = _get_val(result_row, "rules_triggered", "")
    levels_trig  = _get_val(result_row, "levels_triggered", "")

    color      = _risk_color(risk_level)
    status_str = f"  [{status}]" if status else ""

    print(f"Payment:   {payment_id}")
    if fd.PAYMENT_URL_TEMPLATE and payment_id:
        print(f"           {fd.PAYMENT_URL_TEMPLATE.format(payment_id)}")
    if card_name:
        print(f"Name:      {_C['bold']}{card_name}{R}{VERIFIED_BADGE}")
    print(f"Customer:  {customer_id}")
    if cust_url:
        print(f"           {cust_url}")
    if is_verified:
        print(VERIFIED_BADGE)
    if amount:
        print(f"Amount:    {amount}{status_str}")
    sr = _sr_line()
    if sr:
        print(sr)
    print(LINE)
    print(f"Risk Level:  {color}{risk_level:<12}{R}  Risk Score: {risk_score:<8}  Flags: {flag_count}")
    print(LINE)

    if reason_sum:
        reasons = reason_sum.split(" | ")
        levels  = [l.strip() for l in levels_trig.split(",") if l.strip()]
        print("Reasons:")
        for i, (r, lvl) in enumerate(zip(reasons, levels + [""] * len(reasons)), 1):
            rc = _risk_color(lvl) if lvl else ""
            print(f"  {i}. {rc}{r}{R}")

    matched_cid, matched_url = _matched_blocked_url(result_row)
    explanation = _match_explanation(result_row, tx_row)
    if matched_cid:
        print(f"\nMatched blocked user:")
        print(f"  Customer:  {matched_cid}")
        if matched_url:
            print(f"             {matched_url}")
        if explanation:
            print(f"  Match:     {explanation}")

    _IB_LABELS = {
        "AUTH_CODES_INSTANT":        "Flagged auth code",
        "TOKEN_BLOCKED":             "Card token matched blocked user",
        "EMAIL_BLOCKED":             "Email matched blocked user",
        "IP_BLOCKED":                "IP matched blocked user",
        "FRAUD_CODE_ZERO_ACCEPT":    "Auth code 59/83 with 0% acceptance rate",
        "MULTI_NAME_LOW_ACCEPT":     "Multiple card names with low acceptance rate",
        "IP_FRAUD_CODE_ZERO_ACCEPT": "IP match with 59/83 and 0% acceptance rate",
    }
    triggered   = set(rules_trig.replace(" ", "").split(","))
    _IB_INSTANT = {"IP_BLOCKED", "TOKEN_BLOCKED", "AUTH_CODES_INSTANT",
                   "FRAUD_CODE_ZERO_ACCEPT", "MULTI_NAME_LOW_ACCEPT", "IP_FRAUD_CODE_ZERO_ACCEPT"}
    _show_banner = bool(_IB_INSTANT & triggered)
    if not _show_banner and "EMAIL_BLOCKED" in triggered:
        _show_banner = int(result_row.get("_r03_score", 0) or 0) == 100
    if _show_banner:
        fired_ib = (_IB_INSTANT | {"EMAIL_BLOCKED"}) & triggered
        labels   = ", ".join(_IB_LABELS.get(r, r) for r in sorted(fired_ib))
        print(f"{color}{LINE}{R}")
        print(f"{_C['bold']}{color}  !! INSTANT BAN !!{R}")
        print(f"{color}  Reason: {labels}{R}")

    print(f"{color}{SEP}{R}")


# ── Startup ────────────────────────────────────────────────────────────────────

def _load_state(skip_download: bool = False) -> None:
    global _history_df, _blocked_df, _female_names, _name_freq, _verified_customer_ids

    db.init_db()
    print("Loading fraud detection state...")

    if not skip_download:
        since = datetime.now(UTC) - timedelta(days=2)
        print(f"  Refreshing payments (last 2 days from {since.date()})...")
        try:
            dl.download(since=since)
        except SystemExit:
            print("  Warning: payment download failed — continuing with existing DB data.")
        except Exception as exc:
            print(f"  Warning: payment download failed ({exc}) — continuing with existing DB data.")
        print()

    _female_names = fd.load_female_names()
    _name_freq    = fd.load_name_frequency()

    _blocked_df = db.load_blocked_users()
    print(f"  Loaded {len(_blocked_df):,} blocked users from database")

    _history_df = db.load_payments()
    print(f"  Total history: {len(_history_df):,} transactions")

    _verified_customer_ids = db.load_verified_customer_ids()
    print(f"  Loaded {len(_verified_customer_ids):,} verified customer(s)\n")

    if not COINFLOW_VALIDATION_KEY:
        print("Warning: COINFLOW_VALIDATION_KEY not set — signature verification disabled.\n")


# ── Signature verification ─────────────────────────────────────────────────────

def _verify_signature(raw_body: bytes, header_value: str | None) -> bool:
    """Verify a Coinflow-Signature header.

    Header format:  t=1717012345,v1=<hex-digest>
    Signed payload: {timestamp}.{raw_body_string}
    """
    if not COINFLOW_VALIDATION_KEY:
        return True
    if not header_value:
        return False
    try:
        parts = dict(p.split("=", 1) for p in header_value.split(","))
        timestamp = parts.get("t")
        signature = parts.get("v1")
    except Exception:
        return False
    if not timestamp or not signature:
        return False
    signed_payload = f"{timestamp}.{raw_body.decode('utf-8', errors='replace')}"
    expected = hmac.new(
        COINFLOW_VALIDATION_KEY.encode(), signed_payload.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


# ── Payment fetch ──────────────────────────────────────────────────────────────

def _fetch_payment(payment_id: str) -> dict | None:
    if not COINFLOW_API_KEY:
        print("Error: COINFLOW_API_KEY is not set.", file=sys.stderr)
        return None
    clean_id = payment_id.replace("-", "")
    url = f"{COINFLOW_API_URL}/merchant/payments/{clean_id}"
    try:
        resp = requests.get(url, headers={"Authorization": COINFLOW_API_KEY}, timeout=15)
    except requests.exceptions.RequestException as exc:
        print(f"  Network error fetching {payment_id}: {exc}", file=sys.stderr)
        return None
    if resp.status_code in (404, 204) or not resp.content:
        print(f"  Payment {payment_id!r} not found (status {resp.status_code}) — skipping.")
        return None
    if resp.status_code == 401:
        print("  Authentication failed — check COINFLOW_API_KEY.", file=sys.stderr)
        return None
    if not resp.ok:
        print(f"  API error {resp.status_code} for {payment_id}: {resp.text[:200]}", file=sys.stderr)
        return None
    try:
        return resp.json()
    except Exception:
        print(f"  Non-JSON response for {payment_id} (status {resp.status_code})", file=sys.stderr)
        return None


# ── Payment → DataFrame ────────────────────────────────────────────────────────

def _payment_to_df(payment: dict, customer_id_override: str | None = None) -> pd.DataFrame:
    flat    = _flatten(payment)
    renamed = {fd.COLUMN_RENAME_MAP.get(k, k): v for k, v in flat.items()}
    row     = {k: str(v) if v is not None else "" for k, v in renamed.items()}
    df      = pd.DataFrame([row])

    if "customer_id" not in df.columns and "customer" in df.columns:
        df["customer_id"] = df["customer"]

    # Override with the UUID from the webhook payload (same as --customer-id flag)
    if customer_id_override:
        df["customer_id"] = customer_id_override

    if "transaction_created_at" in df.columns:
        df["transaction_created_at"] = df["transaction_created_at"].apply(fd.parse_timestamp)
    if "total_cents" in df.columns:
        df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)

    df["customer_status"] = "Functional"

    for col in fd.COLUMN_RENAME_MAP.values():
        if col not in df.columns:
            df[col] = ""

    if "payment_id" in df.columns:
        df["payment_id"] = df["payment_id"].str.replace("-", "", regex=False)

    return df


# ── Persistence helpers ────────────────────────────────────────────────────────

def _persist_payment(tx_df: pd.DataFrame) -> None:
    """Persist an incoming payment to the database."""
    db.upsert_payment(tx_df)


def _append_to_blocked_list(tx_df: pd.DataFrame, reason_summary: str) -> bool:
    """Persist a newly blocked customer to the DB and update in-memory _blocked_df. Returns True if added."""
    global _blocked_df
    row = tx_df.iloc[0]
    customer_id = str(row.get("customer_id", "")).strip()

    if db.is_customer_blocked(customer_id):
        return False

    new_entry: dict = {}
    for field in fd._BLOCKED_FIELDS:
        new_entry[field] = str(row.get(field, "")).strip()

    first = new_entry.get("card_first_name", "")
    last  = new_entry.get("card_last_name", "")
    new_entry["full_name"]        = f"{first} {last}".strip().lower()
    # Seed all-values columns with the single transaction's values; the next hourly
    # refresh (dl.download → build_blocked_list) will populate full history.
    new_entry["all_card_ips"]     = new_entry.get("card_ip", "")
    new_entry["all_card_emails"]  = new_entry.get("card_email", "")
    new_entry["all_card_tokens"]  = new_entry.get("card_token", "")
    new_entry["all_card_streets"] = new_entry.get("card_street", "")
    new_entry["all_full_names"]   = new_entry["full_name"]
    new_entry["reason_summary"]   = reason_summary
    new_entry["added_at"]         = datetime.now(UTC).isoformat()
    new_entry["source"]           = "webhook_server"

    added = db.upsert_blocked_user(new_entry)

    # Update in-memory blocked_df
    new_row_df = pd.DataFrame([new_entry])
    for col in _BLOCKED_LIST_COLS:
        if col not in new_row_df.columns:
            new_row_df[col] = ""
    _blocked_df = pd.concat([_blocked_df, new_row_df[_BLOCKED_LIST_COLS]], ignore_index=True)
    return added


# ── Coinflow block API ─────────────────────────────────────────────────────────

def _block_in_coinflow(customer_id: str) -> bool:
    """Block a customer via the Coinflow API. Returns True on success."""
    if not customer_id or not COINFLOW_API_KEY:
        return False
    url = f"{COINFLOW_API_URL}/merchant/blocked/{customer_id}"
    try:
        resp = requests.put(
            url,
            json={"reason": "Blocked1", "status": "Blocked"},
            headers={"Authorization": COINFLOW_API_KEY},
            timeout=15,
        )
        return resp.ok
    except requests.exceptions.RequestException as exc:
        print(f"  Coinflow block API error: {exc}", file=sys.stderr)
        return False


def _block_in_coinflow(customer_id: str) -> bool:
    """PUT /merchant/blocked/<id> to block the customer in Coinflow. Returns True on success."""
    if not customer_id or not COINFLOW_API_KEY:
        return False
    url = f"{COINFLOW_API_URL}/merchant/blocked/{customer_id}"
    try:
        resp = requests.put(
            url,
            json={"reason": "Blocked1", "status": "Blocked"},
            headers={"Authorization": COINFLOW_API_KEY, "Content-Type": "application/json"},
            timeout=15,
        )
        return resp.ok
    except requests.exceptions.RequestException as exc:
        print(f"⚠  Coinflow block API error: {exc}")
        return False


# ── Hourly background refresh ──────────────────────────────────────────────────

def _refresh_state() -> None:
    """Download the last 2 hours and reload all in-memory state under the lock."""
    global _history_df, _blocked_df, _female_names, _name_freq, _verified_customer_ids

    ts = datetime.now(_EASTERN).strftime("%H:%M:%S")
    since = datetime.now(UTC) - timedelta(hours=2)
    print(f"\n[{ts}] [refresh] Downloading payments since {since.isoformat()[:16]}...")
    try:
        dl.download(since=since)
    except SystemExit:
        print(f"[{ts}] [refresh] Warning: download failed — reloading from existing DB data.")
    except Exception as exc:
        print(f"[{ts}] [refresh] Warning: download failed ({exc}) — reloading from DB.")

    new_female_names  = fd.load_female_names()
    new_name_freq     = fd.load_name_frequency()
    new_blocked_df    = db.load_blocked_users()
    new_history_df    = db.load_payments()
    new_verified_ids  = db.load_verified_customer_ids()

    new_verified_ids: set = set()
    verified_path = Path(VERIFIED_CUSTOMERS_PATH)
    if verified_path.exists():
        try:
            verified_df = pd.read_csv(verified_path, dtype=str, encoding="utf-8-sig")
            if "customer_id" in verified_df.columns:
                new_verified_ids = set(verified_df["customer_id"].dropna().str.strip().str.lower())
        except Exception as exc:
            print(f"[refresh] Warning: could not reload verified customers: {exc}")

    with _lock:
        _history_df            = new_history_df
        _blocked_df            = new_blocked_df
        _female_names          = new_female_names
        _name_freq             = new_name_freq
        _verified_customer_ids = new_verified_ids

    ts2 = datetime.now(_EASTERN).strftime("%H:%M:%S")
    print(f"[{ts2}] [refresh] Done — {len(new_history_df):,} transactions, "
          f"{len(new_blocked_df):,} blocked users\n")


def _scheduler_thread() -> None:
    while True:
        time.sleep(3600)
        try:
            _refresh_state()
        except Exception as exc:
            print(f"[refresh] Unexpected error: {exc}")


# ── Flask app ──────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/webhook/<token>", methods=["POST"])
def webhook(token: str) -> tuple:
    global _history_df

    if WEBHOOK_PATH_TOKEN and token != WEBHOOK_PATH_TOKEN:
        return jsonify({"error": "not found"}), 404

    raw_body = request.get_data()

    if not _verify_signature(raw_body, request.headers.get("Coinflow-Signature")):
        return jsonify({"error": "invalid signature"}), 401

    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    event_type  = payload.get("eventType", "")
    data        = payload.get("data", {})
    payment_id  = data.get("id", "")
    customer_id = data.get("customerId", "")

    print(f"[{_ts()}] ← {event_type!r}  id={payment_id!r}  customer={customer_id!r}")

    if event_type not in HANDLED_EVENT_TYPES:
        print(f"[{_ts()}] → ignored  eventType={event_type!r}")
        return jsonify({"status": "ignored", "eventType": event_type}), 200

    if not payment_id:
        print(f"[{_ts()}] → rejected  missing data.id  (eventType={event_type!r})")
        return jsonify({"error": "missing data.id"}), 400

    print(f"\n[{_ts()}] → {event_type}  payment={payment_id}  customer={customer_id}")

    payment = _fetch_payment(payment_id)
    if payment is None:
        print(f"[{_ts()}] → skipped  payment={payment_id}  (not found in Coinflow API)")
        return jsonify({"status": "ok", "note": "payment not found"}), 200

    tx_df = _payment_to_df(payment, customer_id_override=customer_id or None)

    with _lock:
        _history_df = pd.concat([_history_df, tx_df], ignore_index=True)
        _persist_payment(tx_df)

        this_cid = _norm_id(str(tx_df.iloc[0].get("customer_id", "")))
        if this_cid and "customer_id" in _history_df.columns:
            cust_history = _history_df[
                _history_df["customer_id"].fillna("").map(_norm_id) == this_cid
            ].copy()
        else:
            cust_history = tx_df.copy()

        total_txns = len(cust_history)
        if total_txns > 0 and "transaction_status" in cust_history.columns:
            failed_count = int((cust_history["transaction_status"].str.upper() == "FAILED").sum())
            success_rate = round((total_txns - failed_count) / total_txns * 100)
        else:
            success_rate = None

        # Exclude the new payment itself from history to avoid double-scoring
        new_pid = _norm_id(str(tx_df.iloc[0].get("payment_id", "")))
        if new_pid and "payment_id" in cust_history.columns:
            history_only = cust_history[
                cust_history["payment_id"].fillna("").map(_norm_id) != new_pid
            ]
        else:
            history_only = pd.DataFrame()

        is_verified  = _norm_id(this_cid) in _verified_customer_ids
        scoring_df   = pd.concat([history_only, tx_df], ignore_index=True)
        blocked_df   = _blocked_df
        female_names = _female_names
        name_freq    = _name_freq
        is_verified  = _norm_id(customer_id) in _verified_customer_ids

    # Normalize timestamps before scoring (avoids tz-naive/tz-aware comparison errors)
    if "transaction_created_at" in scoring_df.columns:
        scoring_df["transaction_created_at"] = pd.to_datetime(
            scoring_df["transaction_created_at"], format="mixed", utc=True, errors="coerce"
        )

    with contextlib.redirect_stdout(io.StringIO()):
        result_df = fd.score_all(scoring_df, blocked_df, female_names, name_freq)

    if not result_df.empty and new_pid:
        new_result = result_df[result_df["payment_id"].fillna("").map(_norm_id) == new_pid]
    else:
        new_result = result_df

    _print_result(event_type, tx_df, new_result,
                  success_rate=success_rate, txn_count=total_txns, is_verified=is_verified)

    if new_result.empty:
        return jsonify({"status": "ok"}), 200

    result_row      = new_result.iloc[0]
    rules_triggered = set(_get_val(result_row, "rules_triggered").replace(" ", "").split(","))
    fired_instant: set = set()
    # Non-email instant-ban rules fire unconditionally
    for rule in INSTANT_BLOCK_RULES - {"EMAIL_BLOCKED"}:
        if rule in rules_triggered:
            fired_instant.add(rule)
    if "EMAIL_BLOCKED" in rules_triggered:
        # Auto-block only on exact email match (score == 100); fuzzy matches flag for review only
        email_score = int(result_row.get("_r03_score", 0) or 0)
        if email_score == 100:
            fired_instant.add("EMAIL_BLOCKED")

    if fired_instant:
        reason_summary = _get_val(result_row, "reason_summary")
        with _lock:
            added = _append_to_blocked_list(tx_df, reason_summary)
        cid_to_block = str(tx_df.iloc[0].get("customer_id", "")).strip()
        blocked_ok   = _block_in_coinflow(cid_to_block)
        fired_str    = ", ".join(sorted(fired_instant))
        if added:
            print(f"[{_ts()}] ⚠  AUTO-BLOCKED: {fired_str} fired — appended to {BLOCKED_LIST_PATH}")
        else:
            print(f"[{_ts()}] ⚠  AUTO-BLOCKED rules fired ({fired_str}) — customer already in blocked list")
        print(f"   Reason: {reason_summary}")
        cid_to_block = str(tx_df.iloc[0].get("customer_id", "")).strip()
        blocked_ok = _block_in_coinflow(cid_to_block)
        if blocked_ok:
            print(f"⚠  Blocked in Coinflow: {cid_to_block}")
        else:
            print(f"⚠  Coinflow block API call failed for {cid_to_block} — block manually")

    return jsonify({"status": "ok"}), 200


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    if not COINFLOW_API_KEY:
        sys.exit(
            "Error: COINFLOW_API_KEY is not set.\n"
            "Add it to your .env file:  COINFLOW_API_KEY=your_key_here"
        )

    parser = argparse.ArgumentParser(
        description="Webhook server — scores Coinflow payments in real-time"
    )
    parser.add_argument("--port", type=int, default=5000,
                        help="Port to listen on (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip the startup payment refresh (useful for quick restarts during testing)")
    args = parser.parse_args()

    _load_state(skip_download=args.skip_download)

    refresh_thread = threading.Thread(target=_scheduler_thread, daemon=True, name="hourly-refresh")
    refresh_thread.start()

    print(f"Listening on {args.host}:{args.port}  →  POST /webhook\n")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
