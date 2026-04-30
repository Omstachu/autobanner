"""
Seed or update blocked_users.csv from a Coinflow transaction CSV/Excel export.

Reads the export, filters customer_status == "Blocked", deduplicates by customer_id
(keeping the most recent transaction), and appends any new customers to blocked_users.csv.
Existing customer_ids are never duplicated.

reason_summary is populated by scoring each blocked customer chronologically against
previously-blocked users — so cross-user signals (email/token matches) are captured without
circular self-matching. Falls back to "Blocked in Coinflow" when no rules fire.

Usage:
    python build_blocked_list.py                        # auto-picks first file in payments/
    python build_blocked_list.py payments/export.csv
    python build_blocked_list.py --output custom.csv
"""

import argparse
import contextlib
import io
import sys
from datetime import datetime, UTC
from pathlib import Path

import pandas as pd

import db
import fraud_detection as fd

BLOCKED_LIST_PATH = "blocked_users.csv"
PAYMENTS_DIR      = "payments"

_BLOCKED_LIST_COLS = fd._BLOCKED_FIELDS + [
    "full_name",
    "all_card_ips", "all_card_emails", "all_card_tokens", "all_card_streets", "all_full_names",
    "reason_summary", "added_at", "source",
]


def _build_reason_by_customer(df: pd.DataFrame, female_names, name_freq) -> dict[str, str]:
    """Score each blocked customer chronologically against previously-blocked users.

    Each customer is scored against only the users who were blocked before them,
    so cross-user EMAIL_BLOCKED / TOKEN_BLOCKED signals are valid, but self-matching
    is impossible. Falls back to "Blocked in Coinflow" when no rules fire.
    """
    if "transaction_created_at" in df.columns:
        df_sorted = df.sort_values("transaction_created_at", ascending=True)
    else:
        df_sorted = df

    blocked_so_far = pd.DataFrame(columns=_BLOCKED_LIST_COLS)
    reason_by_customer: dict[str, str] = {}
    seen_cids: set[str] = set()

    for _, row in df_sorted.iterrows():
        cid    = str(row.get("customer_id", "")).strip()
        status = str(row.get("customer_status", "")).strip()
        if status != "Blocked" or not cid or cid in seen_cids:
            continue
        seen_cids.add(cid)

        # All transactions for this customer, scored as if they were incoming
        cust_hist = df[df["customer_id"].fillna("").str.strip() == cid].copy()
        cust_hist["customer_status"] = "Functional"
        for col in fd.COLUMN_RENAME_MAP.values():
            if col not in cust_hist.columns:
                cust_hist[col] = ""

        with contextlib.redirect_stdout(io.StringIO()):
            result = fd.score_all(cust_hist, blocked_so_far, female_names, name_freq)

        reason = "Blocked in Coinflow"
        if not result.empty and "reason_summary" in result.columns:
            best = result.sort_values("risk_score", ascending=False).iloc[0]
            rsn  = str(best.get("reason_summary", "")).strip()
            if rsn:
                reason = rsn
        reason_by_customer[cid] = reason

        # Add to running blocked list so subsequent users can match against this one
        entry = {f: str(row.get(f, "")).strip() for f in fd._BLOCKED_FIELDS}
        first = entry.get("card_first_name", "")
        last  = entry.get("card_last_name", "")
        entry["full_name"]      = f"{first} {last}".strip().lower()
        entry["reason_summary"] = reason
        entry["added_at"]       = datetime.now(UTC).isoformat()
        entry["source"]         = "seeded_csv"
        blocked_so_far = pd.concat([blocked_so_far, pd.DataFrame([entry])], ignore_index=True)

    return reason_by_customer


def _find_input_file() -> str:
    files = sorted(Path(PAYMENTS_DIR).glob("*"))
    files = [f for f in files if f.suffix.lower() in (".csv", ".xlsx", ".xls")]
    if not files:
        sys.exit(f"No CSV/Excel files found in {PAYMENTS_DIR!r}. Pass a file path explicitly.")
    return str(files[0])


def build(input_path: str, output_path: str) -> None:
    print(f"Loading transactions from {input_path!r}...")
    df = fd._load_file(input_path)
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    df = df.rename(columns={k: v for k, v in fd.COLUMN_RENAME_MAP.items() if k in df.columns})

    if "transaction_created_at" in df.columns:
        df["transaction_created_at"] = df["transaction_created_at"].apply(fd.parse_timestamp)
    if "total_cents" in df.columns:
        df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)

    if "customer_status" not in df.columns:
        sys.exit("Error: 'customer_status' column not found after renaming. Check input file.")

    blocked = df[df["customer_status"].str.strip() == "Blocked"].copy()
    if blocked.empty:
        print("No blocked users found in input data. Nothing to write.")
        return
    print(f"  Found {len(blocked):,} blocked-status rows")

    # Score blocked customers chronologically to build reason_summary
    print("  Scoring blocked customers to determine reason_summary...")
    female_names = fd.load_female_names()
    name_freq    = fd.load_name_frequency()
    reason_by_customer = _build_reason_by_customer(df, female_names, name_freq)

    # Compute full_name on ALL blocked rows before deduplication (needed for all_full_names)
    _fn_first = blocked.get("card_first_name", pd.Series(dtype=str)).fillna("")
    _fn_last  = blocked.get("card_last_name",  pd.Series(dtype=str)).fillna("")
    blocked = blocked.copy()
    blocked["full_name"] = (_fn_first + " " + _fn_last).str.strip().str.lower()
    blocked_all = blocked.copy()  # keep all rows for multi-value aggregation

    # Keep most recent transaction per customer
    if "transaction_created_at" in blocked.columns:
        blocked = blocked.sort_values("transaction_created_at", ascending=False)
    blocked = blocked.drop_duplicates(subset="customer_id", keep="first")
    print(f"  Deduplicated to {len(blocked):,} unique blocked customers")

    # Select only the fields the blocked list needs
    available = [f for f in fd._BLOCKED_FIELDS if f in blocked.columns]
    new_rows = blocked[available].copy()

    # full_name already on blocked; copy it across
    new_rows["full_name"] = blocked["full_name"].values

    # Aggregate all unique values per customer into |||‑separated columns
    _ALL_VALUE_MAP = {
        "all_card_ips":     "card_ip",
        "all_card_emails":  "card_email",
        "all_card_tokens":  "card_token",
        "all_card_streets": "card_street",
        "all_full_names":   "full_name",
    }
    for new_col, src_col in _ALL_VALUE_MAP.items():
        if src_col not in blocked_all.columns:
            new_rows[new_col] = ""
            continue
        agg = (
            blocked_all[["customer_id", src_col]]
            .dropna(subset=[src_col])
            .groupby("customer_id")[src_col]
            .apply(lambda s: "|||".join(sorted({v.strip() for v in s if str(v).strip()})))
        )
        new_rows[new_col] = new_rows["customer_id"].map(agg).fillna("")

    now_str = datetime.now(UTC).isoformat()
    new_rows["reason_summary"] = new_rows["customer_id"].apply(
        lambda cid: reason_by_customer.get(str(cid).strip(), "Blocked in Coinflow")
    )
    new_rows["added_at"] = now_str
    new_rows["source"]   = "seeded_csv"

    output_file = Path(output_path)
    already_existed = 0

    if output_file.exists():
        existing = pd.read_csv(output_file, dtype=str)
        existing_ids = set(existing["customer_id"].dropna().str.strip())
        already_existed = len(new_rows[new_rows["customer_id"].isin(existing_ids)])
        new_rows = new_rows[~new_rows["customer_id"].isin(existing_ids)]
        if new_rows.empty:
            print(f"\nAll {already_existed} customer(s) already in {output_path}. Nothing added.")
            return
        combined = pd.concat([existing, new_rows], ignore_index=True)
    else:
        combined = new_rows

    # Ensure all expected columns exist (fill missing with empty string)
    for col in _BLOCKED_LIST_COLS:
        if col not in combined.columns:
            combined[col] = ""

    combined = combined[_BLOCKED_LIST_COLS]
    combined.to_csv(output_file, index=False, encoding="utf-8-sig")

    print(f"\nWrote {output_path}")
    print(f"  New rows added:    {len(new_rows):,}")
    if already_existed:
        print(f"  Already present:   {already_existed:,} (skipped)")
    print(f"  Total in list:     {len(combined):,}")


def build_from_db() -> None:
    """Read payments from DB, rebuild blocked list, upsert into blocked_users table.

    Replaces build(input_path, output_path) for the Cloud Run / DB workflow.
    Called by download_payments.download() after every refresh.
    """
    print("Loading transactions from database...")
    df = db.load_payments()
    print(f"  Loaded {len(df):,} rows")

    if df.empty or "customer_status" not in df.columns:
        print("No payment data found in database. Nothing to update.")
        return

    blocked = df[df["customer_status"].str.strip() == "Blocked"].copy()
    if blocked.empty:
        print("No blocked users found in database. Nothing to update.")
        return
    print(f"  Found {len(blocked):,} blocked-status rows")

    print("  Scoring blocked customers to determine reason_summary...")
    female_names = fd.load_female_names()
    name_freq    = fd.load_name_frequency()
    reason_by_customer = _build_reason_by_customer(df, female_names, name_freq)

    _fn_first = blocked.get("card_first_name", pd.Series(dtype=str)).fillna("")
    _fn_last  = blocked.get("card_last_name",  pd.Series(dtype=str)).fillna("")
    blocked = blocked.copy()
    blocked["full_name"] = (_fn_first + " " + _fn_last).str.strip().str.lower()
    blocked_all = blocked.copy()

    if "transaction_created_at" in blocked.columns:
        blocked = blocked.sort_values("transaction_created_at", ascending=False)
    blocked = blocked.drop_duplicates(subset="customer_id", keep="first")
    print(f"  Deduplicated to {len(blocked):,} unique blocked customers")

    available = [f for f in fd._BLOCKED_FIELDS if f in blocked.columns]
    new_rows = blocked[available].copy()
    new_rows["full_name"] = blocked["full_name"].values

    _ALL_VALUE_MAP = {
        "all_card_ips":     "card_ip",
        "all_card_emails":  "card_email",
        "all_card_tokens":  "card_token",
        "all_card_streets": "card_street",
        "all_full_names":   "full_name",
    }
    for new_col, src_col in _ALL_VALUE_MAP.items():
        if src_col not in blocked_all.columns:
            new_rows[new_col] = ""
            continue
        agg = (
            blocked_all[["customer_id", src_col]]
            .dropna(subset=[src_col])
            .groupby("customer_id")[src_col]
            .apply(lambda s: "|||".join(sorted({v.strip() for v in s if str(v).strip()})))
        )
        new_rows[new_col] = new_rows["customer_id"].map(agg).fillna("")

    now_str = datetime.now(UTC).isoformat()
    new_rows["reason_summary"] = new_rows["customer_id"].apply(
        lambda cid: reason_by_customer.get(str(cid).strip(), "Blocked in Coinflow")
    )
    new_rows["added_at"] = now_str
    new_rows["source"]   = "seeded_csv"

    for _, row in new_rows.iterrows():
        db.upsert_blocked_user_full(row.to_dict())

    print(f"\nUpserted {len(new_rows):,} blocked users to database")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed blocked_users.csv from a Coinflow export")
    parser.add_argument(
        "input_file", nargs="?", default=None,
        help=f"Path to CSV/Excel export. Defaults to first file in {PAYMENTS_DIR}/",
    )
    parser.add_argument(
        "--output", default=BLOCKED_LIST_PATH,
        help=f"Output CSV path (default: {BLOCKED_LIST_PATH})",
    )
    args = parser.parse_args()
    input_path = args.input_file or _find_input_file()
    build(input_path, args.output)


if __name__ == "__main__":
    main()
