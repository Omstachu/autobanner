"""
Ad-hoc query workspace.

Run with `python -i analyze.py` to drop into a REPL with the DB already loaded.

Available DataFrames:
  payments  — every transaction in the DB
  blocked   — known-bad customers (blocked_users table)
  verified  — manually-reviewed customers (verified_customers table)

Available imports: pd (pandas), np (numpy), fd (fraud_detection module),
and a handful of example query helpers below.

Add your own helpers here as you explore — anything that's a one-shot
question can stay inline at the REPL.
"""

import os
import sys
from dotenv import load_dotenv
import numpy as np
import pandas as pd

load_dotenv()

import db
import fraud_detection as fd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)


def _load() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    print("Loading payments…", flush=True)
    p = db.load_payments()
    print(f"  payments: {len(p):,} rows, {p['customer_id'].nunique():,} customers")
    print("Loading blocked_users…", flush=True)
    b = db.load_blocked_users()
    print(f"  blocked:  {len(b):,} rows")
    print("Loading verified_customers…", flush=True)
    v_ids = db.load_verified_customer_ids()
    v = pd.DataFrame({"customer_id": list(v_ids)})
    print(f"  verified: {len(v):,} rows")
    return p, b, v


payments, blocked, verified = _load()


# ── Example helpers ───────────────────────────────────────────────────────────
# Edit / add freely. Run `users_with_886_then_us_card()` in the REPL.

def has_code(series: pd.Series, code: str) -> pd.Series:
    """Boolean mask: rows whose auth_codes field contains `code` as a token."""
    return series.fillna("").str.split(r"[,\s]+").apply(lambda toks: code in toks)


def users_with_886_then_us_card() -> pd.DataFrame:
    """
    For every customer who had an 886 auth code on some transaction, check whether
    they later used a US-BIN card. Returns a per-customer summary.
    """
    p = payments.sort_values("transaction_created_at").copy()
    p["_has_886"] = has_code(p["auth_codes"], "886")

    rows = []
    for cid, grp in p.groupby("customer_id"):
        if not grp["_has_886"].any():
            continue
        first_886_ts = grp.loc[grp["_has_886"], "transaction_created_at"].min()
        later = grp[grp["transaction_created_at"] > first_886_ts]
        us_later = later[later["bin_country"].str.upper() == "US"]
        rows.append({
            "customer_id":    cid,
            "first_886_at":   first_886_ts,
            "txns_after_886": len(later),
            "us_card_after":  len(us_later) > 0,
            "us_txns_after":  len(us_later),
        })

    out = pd.DataFrame(rows)
    if out.empty:
        print("No customers with 886.")
        return out
    n_total      = len(out)
    n_us_after   = out["us_card_after"].sum()
    print(f"{n_total:,} customers had an 886 code")
    print(f"{n_us_after:,} ({n_us_after / n_total:.0%}) later used a US-BIN card")
    return out


def code_acceptance_rate(code: str) -> dict:
    """Acceptance rate across customers who ever hit `code`."""
    p = payments.copy()
    p["_has"] = has_code(p["auth_codes"], code)
    affected = p[p["customer_id"].isin(p.loc[p["_has"], "customer_id"].unique())]
    if affected.empty:
        return {"customers": 0, "txns": 0, "acceptance_rate": None}
    n_settled = (affected["transaction_status"].str.upper() == "SETTLED").sum()
    return {
        "customers":       affected["customer_id"].nunique(),
        "txns":            len(affected),
        "acceptance_rate": round(n_settled / len(affected), 3),
    }


def customers_with(*codes: str) -> pd.Series:
    """customer_ids that hit ALL of the given auth codes at some point."""
    p = payments
    sets = [
        set(p.loc[has_code(p["auth_codes"], c), "customer_id"].unique())
        for c in codes
    ]
    return pd.Series(sorted(set.intersection(*sets)) if sets else [])


# ── Quick reference printed on load ───────────────────────────────────────────

print()
print("Ready. Try:")
print("  payments.head()")
print("  payments.columns.tolist()")
print("  users_with_886_then_us_card()")
print("  code_acceptance_rate('59')")
print("  customers_with('59', '83')")
print()
