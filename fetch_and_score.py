"""
Fetch a Coinflow payment by ID, score it against the blocked user list, and print results.

If an instant-block rule fires (TOKEN_BLOCKED or EMAIL_BLOCKED by default), the customer
is automatically appended to blocked_users.csv.

Usage:
    python fetch_and_score.py <paymentId>
    python fetch_and_score.py pay_abc123 --customer-id UUID --blocked-list path/to/blocked_users.csv

Setup:
    Copy .env and set COINFLOW_API_KEY.
    Run build_blocked_list.py first to seed blocked_users.csv.
"""

import argparse
import contextlib
import io
import os
import sys
from datetime import datetime, UTC
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

import fraud_detection as fd

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

BLOCKED_LIST_PATH   = "blocked_users.csv"
COINFLOW_API_URL    = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY    = os.getenv("COINFLOW_API_KEY", "")

# Rule names that trigger auto-append to blocked_users.csv when they fire
INSTANT_BLOCK_RULES = {
    "TOKEN_BLOCKED", "EMAIL_BLOCKED", "AUTH_CODES_INSTANT",
    "FRAUD_CODE_ZERO_ACCEPT", "MULTI_NAME_LOW_ACCEPT", "IP_FRAUD_CODE_ZERO_ACCEPT",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

_BLOCKED_LIST_COLS = fd._BLOCKED_FIELDS + [
    "full_name", "reason_summary", "added_at", "source",
]


def _flatten(obj: dict, prefix: str = "", sep: str = ".") -> dict:
    """Recursively flatten nested JSON to dot-notation keys."""
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
    """Strip hyphens, lowercase, and strip whitespace for ID comparisons."""
    return str(s).replace("-", "").lower().strip()


def _fetch_payment(payment_id: str) -> dict:
    """Call the Coinflow API and return the raw payment JSON."""
    if not COINFLOW_API_KEY:
        sys.exit(
            "Error: COINFLOW_API_KEY is not set.\n"
            "Add it to your .env file:  COINFLOW_API_KEY=your_key_here"
        )
    # Webhook IDs arrive as UUID with dashes; strip them for the API endpoint
    payment_id = payment_id.replace("-", "")
    url = f"{COINFLOW_API_URL}/merchant/payments/{payment_id}"
    print(f"  GET {url}")
    resp = requests.get(url, headers={"Authorization": COINFLOW_API_KEY}, timeout=15)
    print(f"  Status: {resp.status_code}  Content-Length: {len(resp.content)} bytes")
    if resp.status_code == 404:
        sys.exit(f"Payment not found: {payment_id!r}")
    if resp.status_code == 401:
        sys.exit("Authentication failed — check your COINFLOW_API_KEY in .env")
    if not resp.ok:
        body = resp.text[:500] if resp.text else "(empty body)"
        sys.exit(f"API error {resp.status_code}:\n{body}")
    if resp.status_code == 204 or not resp.content:
        sys.exit(f"Payment not found: {payment_id!r} (API returned {resp.status_code} — check the ID and environment)")
    try:
        return resp.json()
    except Exception:
        sys.exit(f"API returned non-JSON response (status {resp.status_code}):\n{resp.text[:500]}")


def _payment_to_df(payment: dict, debug: bool = False) -> pd.DataFrame:
    """Convert a Coinflow payment JSON response to a single-row scored-ready DataFrame."""
    flat = _flatten(payment)

    if debug:
        print("\n── Raw flattened API keys ──────────────────────────────")
        for k, v in sorted(flat.items()):
            print(f"  {k!r:60s} = {str(v)[:60]!r}")
        print()

    renamed = {fd.COLUMN_RENAME_MAP.get(k, k): v for k, v in flat.items()}

    if debug:
        print("── Mapped snake_case columns ───────────────────────────")
        for k in sorted(renamed):
            if k in set(fd.COLUMN_RENAME_MAP.values()):
                print(f"  {k!r:40s} = {str(renamed[k])[:60]!r}")
        print()

    # Treat as string first (matches how fraud_detection.py loads CSVs)
    row = {k: str(v) if v is not None else "" for k, v in renamed.items()}
    df = pd.DataFrame([row])

    # The API returns 'customer' as a flat ObjectId string, not a nested object.
    # Map it to customer_id when the nested keys are absent.
    if "customer_id" not in df.columns and "customer" in df.columns:
        df["customer_id"] = df["customer"]

    # Apply the same coercions as fraud_detection.py main()
    if "transaction_created_at" in df.columns:
        df["transaction_created_at"] = df["transaction_created_at"].apply(fd.parse_timestamp)
    if "total_cents" in df.columns:
        df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)

    # Incoming transaction is not pre-blocked — we score it against the blocked list
    df["customer_status"] = "Functional"

    # Ensure every column that fraud_detection.py accesses unconditionally is present.
    # Missing fields simply won't trigger the rules that depend on them.
    for col in fd.COLUMN_RENAME_MAP.values():
        if col not in df.columns:
            df[col] = ""

    if "payment_id" in df.columns:
        df["payment_id"] = df["payment_id"].str.replace("-", "", regex=False)

    return df


def _find_payments_file(explicit_path: str | None = None) -> str | None:
    """Return path to a payments CSV to use for customer history, or None if not found."""
    if explicit_path:
        return explicit_path if Path(explicit_path).exists() else None
    files = sorted(Path("payments").glob("*"))
    files = [f for f in files if f.suffix.lower() in (".csv", ".xlsx", ".xls")]
    return str(files[0]) if files else None


def _load_customer_history(tx_df: pd.DataFrame,
                            payments_file: str | None = None) -> pd.DataFrame:
    """Load prior transactions for this customer from the local payments CSV."""
    p = _find_payments_file(payments_file)
    if not p:
        return pd.DataFrame()
    try:
        hist = fd._load_file(p)
    except Exception:
        return pd.DataFrame()
    hist = hist.rename(columns={k: v for k, v in fd.COLUMN_RENAME_MAP.items() if k in hist.columns})
    if "transaction_created_at" in hist.columns:
        hist["transaction_created_at"] = hist["transaction_created_at"].apply(fd.parse_timestamp)
    if "total_cents" in hist.columns:
        hist["total_cents"] = pd.to_numeric(hist["total_cents"], errors="coerce").fillna(0).astype(int)
    customer_id = _norm_id(str(tx_df.iloc[0].get("customer_id", "")))
    if not customer_id or "customer_id" not in hist.columns:
        return pd.DataFrame()
    history = hist[hist["customer_id"].fillna("").map(_norm_id) == customer_id].copy()
    # Exclude the new payment itself if it already appears in the CSV (avoid double-counting)
    new_pid = _norm_id(str(tx_df.iloc[0].get("payment_id", "")))
    if new_pid and "payment_id" in history.columns:
        history = history[history["payment_id"].fillna("").map(_norm_id) != new_pid]
    for col in fd.COLUMN_RENAME_MAP.values():
        if col not in history.columns:
            history[col] = ""
    return history


def _load_blocked_list(path: str) -> pd.DataFrame:
    """Load blocked_users.csv, or return an empty DataFrame if it doesn't exist yet."""
    p = Path(path)
    if not p.exists():
        print(f"Warning: {path!r} not found — scoring against empty blocked list.", file=sys.stderr)
        return pd.DataFrame(columns=_BLOCKED_LIST_COLS)
    blocked = pd.read_csv(p, dtype=str)
    if "full_name" not in blocked.columns:
        first = blocked.get("card_first_name", pd.Series(dtype=str)).fillna("")
        last  = blocked.get("card_last_name",  pd.Series(dtype=str)).fillna("")
        blocked["full_name"] = (first + " " + last).str.strip().str.lower()
    return blocked


def _append_to_blocked_list(tx_df: pd.DataFrame, reason_summary: str,
                             blocked_list_path: str) -> bool:
    """Append the transaction's identity fields to blocked_users.csv. Returns True if added."""
    p = Path(blocked_list_path)
    row = tx_df.iloc[0]
    customer_id = str(row.get("customer_id", "")).strip()

    if p.exists():
        existing = pd.read_csv(p, dtype=str)
        if customer_id and _norm_id(customer_id) in existing["customer_id"].fillna("").map(_norm_id).values:
            return False  # already present
    else:
        existing = pd.DataFrame(columns=_BLOCKED_LIST_COLS)

    new_entry: dict = {}
    for field in fd._BLOCKED_FIELDS:
        new_entry[field] = str(row.get(field, "")).strip()

    first = new_entry.get("card_first_name", "")
    last  = new_entry.get("card_last_name", "")
    new_entry["full_name"]      = f"{first} {last}".strip().lower()
    new_entry["reason_summary"] = reason_summary
    new_entry["added_at"]       = datetime.now(UTC).isoformat()
    new_entry["source"]         = "fetch_and_score"

    new_row = pd.DataFrame([new_entry])
    combined = pd.concat([existing, new_row], ignore_index=True)
    for col in _BLOCKED_LIST_COLS:
        if col not in combined.columns:
            combined[col] = ""
    combined[_BLOCKED_LIST_COLS].to_csv(p, index=False, encoding="utf-8-sig")
    return True


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
    """Return (customer_id, url) of the matched blocked user, if any."""
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


def _print_result(tx_df: pd.DataFrame, result_df: pd.DataFrame) -> None:
    """Print the scored result to console."""
    W = 70
    SEP  = "═" * W
    LINE = "─" * W

    tx_row = tx_df.iloc[0]
    payment_id  = _get_val(tx_row, "payment_id")
    customer_id = _get_val(tx_row, "customer_id")
    amount      = _format_amount(tx_row)
    status      = _get_val(tx_row, "transaction_status")
    cust_url    = _customer_url(customer_id)

    print(f"\n{SEP}")

    if result_df.empty:
        # No rules fired at all
        amt_str = f"  |  Amount: {amount}" if amount else ""
        print(f"Payment: {payment_id}  |  Customer: {customer_id}{amt_str}")
        print(f"  [{status}]" if status else "")
        print(f"✓ No fraud signals detected")
        print(SEP)
        return

    result_row = result_df.iloc[0]
    risk_level   = _get_val(result_row, "risk_level", "—")
    risk_score   = _get_val(result_row, "risk_score", "0")
    flag_count   = _get_val(result_row, "flag_count", "0")
    reason_sum   = _get_val(result_row, "reason_summary", "")
    rules_trig   = _get_val(result_row, "rules_triggered", "")

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

    # Matched blocked user
    matched_cid, matched_url = _matched_blocked_url(result_row)
    explanation = _match_explanation(result_row, tx_row)
    if matched_cid:
        print(f"\nMatched blocked user:")
        print(f"  Customer:  {matched_cid}")
        if matched_url:
            print(f"             {matched_url}")
        if explanation:
            print(f"  Match:     {explanation}")

    _IB_RULES = {"IP_BLOCKED", "TOKEN_BLOCKED", "EMAIL_BLOCKED", "AUTH_CODES_INSTANT",
                 "FRAUD_CODE_ZERO_ACCEPT", "MULTI_NAME_LOW_ACCEPT", "IP_FRAUD_CODE_ZERO_ACCEPT"}
    _IB_LABELS = {
        "AUTH_CODES_INSTANT":        "Flagged auth code",
        "TOKEN_BLOCKED":             "Card token matched blocked user",
        "EMAIL_BLOCKED":             "Email matched blocked user",
        "IP_BLOCKED":                "IP matched blocked user",
        "FRAUD_CODE_ZERO_ACCEPT":    "Auth code 59/83 with 0% acceptance rate",
        "MULTI_NAME_LOW_ACCEPT":     "Multiple card names with low acceptance rate",
        "IP_FRAUD_CODE_ZERO_ACCEPT": "IP match with 59/83 and 0% acceptance rate",
    }
    fired_ib = _IB_RULES & set(rules_trig.replace(" ", "").split(","))
    if fired_ib:
        print(LINE)
        print("  !! INSTANT BAN !!")
        labels = ", ".join(_IB_LABELS.get(r, r) for r in sorted(fired_ib))
        print(f"  Reason: {labels}")

    print(SEP)


def score(payment_id: str, blocked_list_path: str, customer_id: str | None = None,
          payments_file: str | None = None, debug: bool = False) -> None:
    blocked_df   = _load_blocked_list(blocked_list_path)
    female_names = fd.load_female_names()
    name_freq    = fd.load_name_frequency()

    print(f"Fetching payment {payment_id!r}...")
    payment = _fetch_payment(payment_id)
    tx_df   = _payment_to_df(payment, debug=debug)

    if customer_id:
        tx_df["customer_id"] = customer_id

    history_df = _load_customer_history(tx_df, payments_file)
    if not history_df.empty:
        print(f"  Loaded {len(history_df)} prior transaction(s) for customer context")
        scoring_df = pd.concat([history_df, tx_df], ignore_index=True)
    else:
        scoring_df = tx_df

    # Normalize timestamps to tz-aware UTC — history (CSV) produces tz-naive while
    # the API response can produce tz-aware, causing sort failures in score_all.
    if "transaction_created_at" in scoring_df.columns:
        scoring_df["transaction_created_at"] = pd.to_datetime(
            scoring_df["transaction_created_at"], utc=True, errors="coerce"
        )

    # Suppress score_all()'s internal progress prints
    with contextlib.redirect_stdout(io.StringIO()):
        result_df = fd.score_all(scoring_df, blocked_df, female_names, name_freq)

    # Filter to just the new payment's result row
    new_pid = _norm_id(str(tx_df.iloc[0].get("payment_id", "")))
    if not result_df.empty and new_pid:
        new_result = result_df[result_df["payment_id"].fillna("").map(_norm_id) == new_pid]
    else:
        new_result = result_df

    _print_result(tx_df, new_result)

    if new_result.empty:
        return

    result_row = new_result.iloc[0]
    rules_triggered = set(_get_val(result_row, "rules_triggered").replace(" ", "").split(","))
    fired_instant   = rules_triggered & INSTANT_BLOCK_RULES

    if fired_instant:
        reason_summary = _get_val(result_row, "reason_summary")
        added = _append_to_blocked_list(tx_df, reason_summary, blocked_list_path)
        fired_str = ", ".join(sorted(fired_instant))
        if added:
            print(f"⚠  AUTO-BLOCKED: {fired_str} fired — appended to {blocked_list_path}")
        else:
            print(f"⚠  AUTO-BLOCKED rules fired ({fired_str}) — customer already in blocked list")
        print(f"   Reason: {reason_summary}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch a Coinflow payment by ID and score it for fraud risk"
    )
    parser.add_argument("payment_id", help="Coinflow payment ID to fetch and score")
    parser.add_argument(
        "--customer-id", default=None,
        help="Customer UUID (from webhook payload) — overrides the ObjectId in the API response",
    )
    parser.add_argument(
        "--blocked-list", default=BLOCKED_LIST_PATH,
        help=f"Path to blocked_users.csv (default: {BLOCKED_LIST_PATH})",
    )
    parser.add_argument(
        "--payments-file", default=None,
        help="Path to transaction CSV for customer history context (default: auto-detect from payments/)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print raw API response keys and column mapping for diagnostics",
    )
    args = parser.parse_args()
    score(args.payment_id, args.blocked_list, customer_id=args.customer_id,
          payments_file=args.payments_file, debug=args.debug)


if __name__ == "__main__":
    main()
