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
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request

import download_payments as dl
import fraud_detection as fd

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────

COINFLOW_API_URL         = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY         = os.getenv("COINFLOW_API_KEY", "")
COINFLOW_VALIDATION_KEY  = os.getenv("COINFLOW_VALIDATION_KEY", "")

BLOCKED_LIST_PATH  = "blocked_users.csv"
LIVE_PAYMENTS_PATH = "live_payments.csv"

# Rules that trigger auto-append to blocked_users.csv (not IP_BLOCKED — shared IPs)
INSTANT_BLOCK_RULES = {"TOKEN_BLOCKED", "EMAIL_BLOCKED"}

HANDLED_EVENT_TYPES = {"Settled", "Card Payment Authorized", "Card Payment Declined"}

# ── Server state ───────────────────────────────────────────────────────────────

_lock = threading.Lock()
_history_df:  pd.DataFrame = pd.DataFrame()
_blocked_df:  pd.DataFrame = pd.DataFrame()
_female_names: set         = set()
_name_freq:    dict        = {}

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


def _print_result(event_type: str, tx_df: pd.DataFrame, result_df: pd.DataFrame) -> None:
    W    = 70
    SEP  = "═" * W
    LINE = "─" * W

    tx_row      = tx_df.iloc[0]
    payment_id  = _get_val(tx_row, "payment_id")
    customer_id = _get_val(tx_row, "customer_id")
    amount      = _format_amount(tx_row)
    status      = _get_val(tx_row, "transaction_status")
    cust_url    = _customer_url(customer_id)

    print(f"\n{SEP}")
    print(f"[{event_type}]")

    if result_df.empty:
        amt_str = f"  |  Amount: {amount}" if amount else ""
        print(f"Payment: {payment_id}  |  Customer: {customer_id}{amt_str}")
        if status:
            print(f"  [{status}]")
        print("✓ No fraud signals detected")
        print(SEP)
        return

    result_row = result_df.iloc[0]
    risk_level = _get_val(result_row, "risk_level", "—")
    risk_score = _get_val(result_row, "risk_score", "0")
    flag_count = _get_val(result_row, "flag_count", "0")
    reason_sum = _get_val(result_row, "reason_summary", "")
    rules_trig = _get_val(result_row, "rules_triggered", "")

    status_str = f"  [{status}]" if status else ""

    print(f"Payment:   {payment_id}")
    if fd.PAYMENT_URL_TEMPLATE and payment_id:
        print(f"           {fd.PAYMENT_URL_TEMPLATE.format(payment_id)}")
    print(f"Customer:  {customer_id}")
    if cust_url:
        print(f"           {cust_url}")
    if amount:
        print(f"Amount:    {amount}{status_str}")
    print(LINE)
    print(f"Risk Level:  {risk_level:<12}  Risk Score: {risk_score:<8}  Flags: {flag_count}")
    print(LINE)

    if reason_sum:
        reasons = reason_sum.split(" | ")
        print("Reasons:")
        for i, r in enumerate(reasons, 1):
            print(f"  {i}. {r}")

    matched_cid, matched_url = _matched_blocked_url(result_row)
    explanation = _match_explanation(result_row, tx_row)
    if matched_cid:
        print(f"\nMatched blocked user:")
        print(f"  Customer:  {matched_cid}")
        if matched_url:
            print(f"             {matched_url}")
        if explanation:
            print(f"  Match:     {explanation}")

    triggered = set(rules_trig.replace(" ", "").split(","))
    _show_banner = bool({"IP_BLOCKED", "TOKEN_BLOCKED"} & triggered)
    if not _show_banner and "EMAIL_BLOCKED" in triggered:
        _show_banner = int(result_row.get("_r03_score", 0) or 0) == 100
    if _show_banner:
        print(LINE)
        print("  !! INSTANT BAN !!")

    print(SEP)


# ── Startup ────────────────────────────────────────────────────────────────────

def _load_state(skip_download: bool = False) -> None:
    global _history_df, _blocked_df, _female_names, _name_freq

    print("Loading fraud detection state...")

    if not skip_download:
        since = datetime.now(UTC) - timedelta(days=2)
        print(f"  Refreshing payments (last 2 days from {since.date()})...")
        try:
            dl.download(since=since)
        except SystemExit:
            print("  Warning: payment download failed — continuing with existing CSV.")
        except Exception as exc:
            print(f"  Warning: payment download failed ({exc}) — continuing with existing CSV.")
        print()

    _female_names = fd.load_female_names()
    _name_freq    = fd.load_name_frequency()

    # Blocked users
    blocked_path = Path(BLOCKED_LIST_PATH)
    if blocked_path.exists():
        blocked_df = pd.read_csv(blocked_path, dtype=str, encoding="utf-8-sig")
        if "full_name" not in blocked_df.columns:
            first = blocked_df.get("card_first_name", pd.Series(dtype=str)).fillna("")
            last  = blocked_df.get("card_last_name",  pd.Series(dtype=str)).fillna("")
            blocked_df["full_name"] = (first + " " + last).str.strip().str.lower()
        _blocked_df = blocked_df
        print(f"  Loaded {len(_blocked_df):,} blocked users from {BLOCKED_LIST_PATH}")
    else:
        print(f"  Warning: {BLOCKED_LIST_PATH!r} not found — scoring against empty blocked list.")

    # Payment history — auto-detect first file in payments/
    history_df = pd.DataFrame()
    payments_dir = Path("payments")
    if payments_dir.exists():
        csv_files = sorted(
            f for f in payments_dir.iterdir()
            if f.suffix.lower() in (".csv", ".xlsx", ".xls")
        )
        if csv_files:
            try:
                history_df = pd.read_csv(csv_files[0], dtype=str, encoding="utf-8-sig")
                history_df = history_df.rename(
                    columns={k: v for k, v in fd.COLUMN_RENAME_MAP.items()
                             if k in history_df.columns}
                )
                print(f"  Loaded {len(history_df):,} transactions from {csv_files[0].name}")
            except Exception as exc:
                print(f"  Warning: could not load {csv_files[0]}: {exc}")

    # Merge live_payments.csv if present (crash recovery)
    live_path = Path(LIVE_PAYMENTS_PATH)
    if live_path.exists():
        try:
            live_df = pd.read_csv(live_path, dtype=str, encoding="utf-8-sig")
            if not live_df.empty:
                combined = pd.concat([history_df, live_df], ignore_index=True)
                if "payment_id" in combined.columns:
                    before = len(combined)
                    combined = combined.drop_duplicates(subset=["payment_id"], keep="last")
                    print(f"  Merged {len(live_df):,} row(s) from {LIVE_PAYMENTS_PATH} "
                          f"({before - len(combined):,} duplicate(s) removed)")
                else:
                    print(f"  Merged {len(live_df):,} row(s) from {LIVE_PAYMENTS_PATH}")
                history_df = combined
        except Exception as exc:
            print(f"  Warning: could not load {LIVE_PAYMENTS_PATH}: {exc}")

    _history_df = history_df
    print(f"  Total history: {len(_history_df):,} transactions\n")

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

def _append_to_live_csv(tx_df: pd.DataFrame) -> None:
    live_path = Path(LIVE_PAYMENTS_PATH)
    if not live_path.exists():
        tx_df.to_csv(live_path, mode="w", header=True, index=False, encoding="utf-8-sig")
    else:
        # Align to the header established by the first write so rows never have more
        # or fewer columns than the header (API responses vary in their totals fields).
        existing_cols = pd.read_csv(live_path, nrows=0, encoding="utf-8-sig").columns.tolist()
        aligned = tx_df.reindex(columns=existing_cols, fill_value="")
        aligned.to_csv(live_path, mode="a", header=False, index=False, encoding="utf-8-sig")


def _append_to_blocked_list(tx_df: pd.DataFrame, reason_summary: str) -> bool:
    """Append to blocked_users.csv and update in-memory _blocked_df. Returns True if added."""
    global _blocked_df
    p   = Path(BLOCKED_LIST_PATH)
    row = tx_df.iloc[0]
    customer_id = str(row.get("customer_id", "")).strip()

    if not _blocked_df.empty and "customer_id" in _blocked_df.columns:
        if customer_id and _norm_id(customer_id) in _blocked_df["customer_id"].fillna("").map(_norm_id).values:
            return False

    existing = pd.read_csv(p, dtype=str) if p.exists() else pd.DataFrame(columns=_BLOCKED_LIST_COLS)

    new_entry: dict = {}
    for field in fd._BLOCKED_FIELDS:
        new_entry[field] = str(row.get(field, "")).strip()

    first = new_entry.get("card_first_name", "")
    last  = new_entry.get("card_last_name", "")
    new_entry["full_name"]       = f"{first} {last}".strip().lower()
    # Seed all-values columns with the single transaction's values; the next hourly
    # refresh (dl.download → build_blocked_list) will populate full history.
    new_entry["all_card_ips"]    = new_entry.get("card_ip", "")
    new_entry["all_card_emails"] = new_entry.get("card_email", "")
    new_entry["all_card_tokens"] = new_entry.get("card_token", "")
    new_entry["all_card_streets"]= new_entry.get("card_street", "")
    new_entry["all_full_names"]  = new_entry["full_name"]
    new_entry["reason_summary"]  = reason_summary
    new_entry["added_at"]        = datetime.now(UTC).isoformat()
    new_entry["source"]          = "auto_detected"

    new_row_df = pd.DataFrame([new_entry])
    combined   = pd.concat([existing, new_row_df], ignore_index=True)
    for col in _BLOCKED_LIST_COLS:
        if col not in combined.columns:
            combined[col] = ""
    combined[_BLOCKED_LIST_COLS].to_csv(p, index=False, encoding="utf-8-sig")

    # Update in-memory blocked_df
    for col in _BLOCKED_LIST_COLS:
        if col not in new_row_df.columns:
            new_row_df[col] = ""
    _blocked_df = pd.concat([_blocked_df, new_row_df[_BLOCKED_LIST_COLS]], ignore_index=True)
    return True


# ── Hourly background refresh ──────────────────────────────────────────────────

def _refresh_state() -> None:
    """Download the last 2 hours and reload all in-memory state under the lock."""
    global _history_df, _blocked_df, _female_names, _name_freq

    ts = datetime.now(UTC).strftime("%H:%M:%S")
    since = datetime.now(UTC) - timedelta(hours=2)
    print(f"\n[{ts}] [refresh] Downloading payments since {since.isoformat()[:16]}...")
    try:
        dl.download(since=since)
    except SystemExit:
        print(f"[{ts}] [refresh] Warning: download failed — reloading from existing CSV.")
    except Exception as exc:
        print(f"[{ts}] [refresh] Warning: download failed ({exc}) — reloading from existing CSV.")

    new_female_names = fd.load_female_names()
    new_name_freq    = fd.load_name_frequency()

    new_blocked_df = pd.DataFrame()
    blocked_path = Path(BLOCKED_LIST_PATH)
    if blocked_path.exists():
        try:
            new_blocked_df = pd.read_csv(blocked_path, dtype=str, encoding="utf-8-sig")
            if "full_name" not in new_blocked_df.columns:
                first = new_blocked_df.get("card_first_name", pd.Series(dtype=str)).fillna("")
                last  = new_blocked_df.get("card_last_name",  pd.Series(dtype=str)).fillna("")
                new_blocked_df["full_name"] = (first + " " + last).str.strip().str.lower()
        except Exception as exc:
            print(f"[refresh] Warning: could not reload blocked list: {exc}")

    new_history_df = pd.DataFrame()
    payments_dir = Path("payments")
    if payments_dir.exists():
        csv_files = sorted(
            f for f in payments_dir.iterdir()
            if f.suffix.lower() in (".csv", ".xlsx", ".xls")
        )
        if csv_files:
            try:
                new_history_df = pd.read_csv(csv_files[0], dtype=str, encoding="utf-8-sig")
                new_history_df = new_history_df.rename(
                    columns={k: v for k, v in fd.COLUMN_RENAME_MAP.items()
                             if k in new_history_df.columns}
                )
            except Exception as exc:
                print(f"[refresh] Warning: could not reload payments CSV: {exc}")

    live_path = Path(LIVE_PAYMENTS_PATH)
    if live_path.exists():
        try:
            live_df = pd.read_csv(live_path, dtype=str, encoding="utf-8-sig")
            if not live_df.empty:
                combined = pd.concat([new_history_df, live_df], ignore_index=True)
                if "payment_id" in combined.columns:
                    combined = combined.drop_duplicates(subset=["payment_id"], keep="last")
                new_history_df = combined
        except Exception as exc:
            print(f"[refresh] Warning: could not reload live payments: {exc}")

    with _lock:
        _history_df   = new_history_df
        _blocked_df   = new_blocked_df
        _female_names = new_female_names
        _name_freq    = new_name_freq

    ts2 = datetime.now(UTC).strftime("%H:%M:%S")
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


@app.route("/webhook", methods=["POST"])
def webhook() -> tuple:
    global _history_df

    raw_body = request.get_data()

    if not _verify_signature(raw_body, request.headers.get("Coinflow-Signature")):
        return jsonify({"error": "invalid signature"}), 401

    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    event_type = payload.get("eventType", "")
    if event_type not in HANDLED_EVENT_TYPES:
        return jsonify({"status": "ignored", "eventType": event_type}), 200

    data        = payload.get("data", {})
    payment_id  = data.get("id", "")
    customer_id = data.get("customerId", "")

    if not payment_id:
        return jsonify({"error": "missing data.id"}), 400

    print(f"\n→ {event_type}  payment={payment_id}  customer={customer_id}")

    payment = _fetch_payment(payment_id)
    if payment is None:
        return jsonify({"status": "ok", "note": "payment not found"}), 200

    tx_df = _payment_to_df(payment, customer_id_override=customer_id or None)

    with _lock:
        _history_df = pd.concat([_history_df, tx_df], ignore_index=True)
        _append_to_live_csv(tx_df)

        this_cid = _norm_id(str(tx_df.iloc[0].get("customer_id", "")))
        if this_cid and "customer_id" in _history_df.columns:
            cust_history = _history_df[
                _history_df["customer_id"].fillna("").map(_norm_id) == this_cid
            ].copy()
        else:
            cust_history = tx_df.copy()

        # Exclude the new payment itself from history to avoid double-scoring
        new_pid = _norm_id(str(tx_df.iloc[0].get("payment_id", "")))
        if new_pid and "payment_id" in cust_history.columns:
            history_only = cust_history[
                cust_history["payment_id"].fillna("").map(_norm_id) != new_pid
            ]
        else:
            history_only = pd.DataFrame()

        scoring_df   = pd.concat([history_only, tx_df], ignore_index=True)
        blocked_df   = _blocked_df
        female_names = _female_names
        name_freq    = _name_freq

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

    _print_result(event_type, tx_df, new_result)

    if new_result.empty:
        return jsonify({"status": "ok"}), 200

    result_row      = new_result.iloc[0]
    rules_triggered = set(_get_val(result_row, "rules_triggered").replace(" ", "").split(","))
    fired_instant: set = set()
    if "TOKEN_BLOCKED" in rules_triggered:
        fired_instant.add("TOKEN_BLOCKED")
    if "EMAIL_BLOCKED" in rules_triggered:
        # Auto-block only on exact email match (score == 100); fuzzy matches flag for review only
        email_score = int(result_row.get("_r03_score", 0) or 0)
        if email_score == 100:
            fired_instant.add("EMAIL_BLOCKED")

    if fired_instant:
        reason_summary = _get_val(result_row, "reason_summary")
        with _lock:
            added = _append_to_blocked_list(tx_df, reason_summary)
        fired_str = ", ".join(sorted(fired_instant))
        if added:
            print(f"⚠  AUTO-BLOCKED: {fired_str} fired — appended to {BLOCKED_LIST_PATH}")
        else:
            print(f"⚠  AUTO-BLOCKED rules fired ({fired_str}) — customer already in blocked list")

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
