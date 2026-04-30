"""One-time script: seed the payments table from the existing CSV export. Delete after use."""
from pathlib import Path

import pandas as pd

import db
import fraud_detection as fd

db.init_db()

csv_files = sorted(
    f for f in Path("payments").iterdir()
    if f.suffix.lower() in (".csv", ".xlsx", ".xls")
)
if not csv_files:
    raise SystemExit("No CSV files found in payments/")

print(f"Loading {csv_files[0].name}...")
df = pd.read_csv(csv_files[0], dtype=str, encoding="utf-8-sig")
df = df.rename(columns={k: v for k, v in fd.COLUMN_RENAME_MAP.items() if k in df.columns})

if "transaction_created_at" in df.columns:
    df["transaction_created_at"] = df["transaction_created_at"].apply(fd.parse_timestamp)
if "total_cents" in df.columns:
    df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)

print(f"Upserting {len(df):,} rows...")
count = db.upsert_payments_batch(df)
print(f"Done — seeded {count:,} payments into database")
