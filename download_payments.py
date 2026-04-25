"""
Download all Coinflow payments via API and save as a single CSV to payments/.
Any existing CSV/Excel files in payments/ are replaced.
After downloading, blocked_users.csv is automatically updated.

Usage:
    python download_payments.py                      # last 90 days
    python download_payments.py --days 180           # last N days
    python download_payments.py --all-time           # full history
    python download_payments.py --since 2026-01-01
    python download_payments.py --since 2026-01-01 --until 2026-04-01
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

import build_blocked_list as bbl

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

COINFLOW_API_URL  = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY  = os.getenv("COINFLOW_API_KEY", "")
PAYMENTS_DIR      = "payments"
BLOCKED_LIST_PATH = "blocked_users.csv"
PAGE_SIZE         = 500
DEFAULT_DAYS      = 90
MAX_RETRIES       = 3
RETRY_BACKOFF     = 2.0  # seconds; doubles each retry

# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _to_epoch_ms(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1000))


def _save_partial(rows: list[dict], payments_dir: Path) -> Path:
    """Write whatever rows were fetched so far to a partial CSV and return its path."""
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    out_path = payments_dir / f"payments-{date_str}-partial.csv"
    pd.DataFrame(rows).to_csv(out_path, index=False, encoding="utf-8-sig")
    return out_path


def _fetch_page(since_ms: str | None, until_ms: str | None, page: int) -> list:
    """Fetch one page of payments from the API, retrying on transient errors."""
    if not COINFLOW_API_KEY:
        sys.exit(
            "Error: COINFLOW_API_KEY is not set.\n"
            "Add it to your .env file:  COINFLOW_API_KEY=your_key_here"
        )
    params: dict = {"page": page, "limit": PAGE_SIZE, "sortBy": "createdAt", "sortDirection": 1}
    if since_ms:
        params["since"] = since_ms
    if until_ms:
        params["until"] = until_ms

    url = f"{COINFLOW_API_URL}/merchant/payments"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                headers={"Authorization": COINFLOW_API_KEY},
                params=params,
                timeout=30,
            )
        except requests.exceptions.RequestException as exc:
            if attempt == MAX_RETRIES:
                raise
            wait = RETRY_BACKOFF * (2 ** (attempt - 1))
            print(f"\n    Network error ({exc}); retrying in {wait:.0f}s (attempt {attempt}/{MAX_RETRIES})...",
                  end=" ", flush=True)
            time.sleep(wait)
            continue

        if resp.status_code == 401:
            sys.exit("Authentication failed — check your COINFLOW_API_KEY in .env")

        if resp.ok:
            return resp.json()

        # Transient server error — retry
        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF * (2 ** (attempt - 1))
            print(f"\n    API error {resp.status_code}; retrying in {wait:.0f}s "
                  f"(attempt {attempt}/{MAX_RETRIES})...", end=" ", flush=True)
            time.sleep(wait)
        else:
            body = resp.text[:500] if resp.text else "(empty body)"
            raise RuntimeError(f"API error {resp.status_code} after {MAX_RETRIES} attempts:\n{body}")

    return []  # unreachable


def download(since: datetime | None = None, until: datetime | None = None) -> None:
    since_ms = _to_epoch_ms(since) if since else None
    until_ms = _to_epoch_ms(until) if until else None

    payments_dir = Path(PAYMENTS_DIR)
    payments_dir.mkdir(exist_ok=True)

    all_rows: list[dict] = []
    page = 1

    try:
        while True:
            print(f"  Fetching page {page}...", end=" ", flush=True)
            batch = _fetch_page(since_ms, until_ms, page)
            if not batch:
                print("(empty — done)")
                break
            print(f"{len(batch)} payments")
            for payment in batch:
                all_rows.append(_flatten(payment))
            if len(batch) < PAGE_SIZE:
                break
            page += 1

    except (RuntimeError, requests.exceptions.RequestException) as exc:
        print(f"\n  Error on page {page}: {exc}")
        if all_rows:
            partial = _save_partial(all_rows, payments_dir)
            print(f"  Saved {len(all_rows):,} payments fetched so far to: {partial}")
        sys.exit(1)

    if not all_rows:
        print("No payments found for the specified date range.")
        return

    print(f"\n  Total downloaded: {len(all_rows):,} payments")

    new_df = pd.DataFrame(all_rows)

    # Merge with existing CSV if present, deduplicating on paymentId
    existing_files = sorted(
        f for f in payments_dir.iterdir()
        if f.suffix.lower() in (".csv", ".xlsx", ".xls")
    )
    old_path = existing_files[0] if existing_files else None

    if old_path:
        existing_df = pd.read_csv(old_path, dtype=str)
        combined = pd.concat([existing_df, new_df], ignore_index=True)
        before = len(combined)
        combined = combined.drop_duplicates(subset=["paymentId"], keep="last")
        print(f"  Merged with {old_path.name}: {before - len(combined):,} duplicate(s) removed, {len(combined):,} total rows")
    else:
        combined = new_df

    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    out_path = payments_dir / f"payments-{date_str}.csv"
    combined.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"  Wrote:   {out_path}  ({len(combined):,} rows)")

    if old_path and old_path != out_path:
        old_path.unlink()
        print(f"  Removed: {old_path.name}")

    # Update blocked_users.csv with any newly blocked customers
    print(f"\nUpdating {BLOCKED_LIST_PATH}...")
    bbl.build(str(out_path), BLOCKED_LIST_PATH)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download Coinflow payments to payments/ and update blocked_users.csv"
    )
    date_group = parser.add_mutually_exclusive_group()
    date_group.add_argument(
        "--since", default=None,
        help="Start date in YYYY-MM-DD format (UTC)",
    )
    date_group.add_argument(
        "--yesterday", action="store_true",
        help="Fetch from yesterday midnight UTC (shorthand for --since <yesterday>)",
    )
    date_group.add_argument(
        "--all-time", action="store_true",
        help="Fetch full payment history with no date filter",
    )
    parser.add_argument(
        "--until", default=None,
        help="End date in YYYY-MM-DD format (UTC, default: now)",
    )
    parser.add_argument(
        "--days", type=int, default=DEFAULT_DAYS,
        help=f"Number of past days to fetch when --since is not set (default: {DEFAULT_DAYS})",
    )
    args = parser.parse_args()

    now = datetime.now(UTC)

    if args.all_time:
        since = None
    elif args.yesterday:
        since = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    elif args.since:
        since = datetime.fromisoformat(args.since).replace(tzinfo=UTC)
    else:
        since = now - timedelta(days=args.days)

    until = datetime.fromisoformat(args.until).replace(tzinfo=UTC) if args.until else now

    if since:
        print(f"Downloading payments from {since.date()} to {until.date()}...")
    else:
        print(f"Downloading all payments (until {until.date()})...")

    download(since=since, until=until)


if __name__ == "__main__":
    main()
