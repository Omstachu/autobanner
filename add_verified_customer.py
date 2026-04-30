"""
Add a customer to the verified_customers table by payment ID.

Fetches the payment from the Coinflow API to get the customer ID and card details,
then inserts a row into the database. Being on this list means the customer has been
previously reviewed — it does not mean they cannot commit fraud.

Usage:
    python add_verified_customer.py <paymentId>
    python add_verified_customer.py <paymentId> --note "manually reviewed 2026-04-25"
"""

import argparse
import os
import sys
from datetime import datetime, UTC

import requests
from dotenv import load_dotenv

import db
import fraud_detection as fd

load_dotenv()

COINFLOW_API_URL = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY = os.getenv("COINFLOW_API_KEY", "")


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


def _fetch_payment(payment_id: str) -> dict:
    clean_id = payment_id.replace("-", "")
    url = f"{COINFLOW_API_URL}/merchant/payments/{clean_id}"
    try:
        resp = requests.get(url, headers={"Authorization": COINFLOW_API_KEY}, timeout=15)
    except requests.exceptions.RequestException as exc:
        sys.exit(f"Network error: {exc}")
    if resp.status_code == 404:
        sys.exit(f"Payment {payment_id!r} not found.")
    if resp.status_code == 401:
        sys.exit("Authentication failed — check COINFLOW_API_KEY in .env")
    if not resp.ok:
        sys.exit(f"API error {resp.status_code}: {resp.text[:200]}")
    try:
        return resp.json()
    except Exception:
        sys.exit(f"Non-JSON response (status {resp.status_code})")


def main() -> None:
    if not COINFLOW_API_KEY:
        sys.exit("Error: COINFLOW_API_KEY is not set in .env")

    parser = argparse.ArgumentParser(description="Add a customer to the verified list")
    parser.add_argument("payment_id", help="Coinflow payment ID")
    parser.add_argument("--note", default="", help="Optional note about why this customer is verified")
    args = parser.parse_args()

    print(f"Fetching payment {args.payment_id}...")
    payment = _fetch_payment(args.payment_id)

    flat    = _flatten(payment)
    renamed = {fd.COLUMN_RENAME_MAP.get(k, k): v for k, v in flat.items()}
    row     = {k: str(v).strip() if v is not None else "" for k, v in renamed.items()}

    customer_id = row.get("customer_id") or row.get("customer", "")
    if not customer_id:
        sys.exit("Could not determine customer_id from payment response.")

    first = row.get("card_first_name", "").strip().title()
    last  = row.get("card_last_name",  "").strip().title()
    email = row.get("card_email", "").strip()
    name  = f"{first} {last}".strip() or "(unknown)"

    db.init_db()
    added = db.add_verified_customer({
        "customer_id":          customer_id,
        "card_first_name":      first,
        "card_last_name":       last,
        "card_email":           email,
        "note":                 args.note,
        "added_at":             datetime.now(UTC).isoformat(),
        "added_by_payment_id":  args.payment_id,
    })

    if not added:
        print(f"Customer {name} ({customer_id}) is already in the verified list.")
        return

    print(f"Added: {name}  |  {customer_id}")
    if email:
        print(f"Email: {email}")
    print("Note: this flags the customer as previously reviewed, not permanently safe.")


if __name__ == "__main__":
    main()
