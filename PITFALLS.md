# Pitfalls & Things to Watch Out For

Operational gotchas and non-obvious behaviors discovered while building and running this system.

---

## Setup / First-Run Order

**You must run scripts in this order or things will silently fail:**
1. `build_female_names.py` — if `female_names.csv` is missing, `FEMALE_NAME` and `GENDER_SWITCH` rules produce no results without any error
2. `download_payments.py` (or drop a CSV into `payments/`) — needed before any scoring
3. `build_blocked_list.py` — if `blocked_users.csv` is missing or empty, rules EMAIL_BLOCKED, TOKEN_BLOCKED, IP_BLOCKED, NAME_BLOCKED, and STREET_BLOCKED will never fire

---

## Sandbox vs. Production API Key

The sandbox endpoint (`api-sandbox.coinflow.cash`) requires a sandbox API key. A production key will get a 400 error: *"Invalid api key, environment is sandbox, key is for prod"*. The scripts default to the **production** endpoint (`api.coinflow.cash`). If you ever test against sandbox, you need a separate sandbox key.

---

## fetch_and_score.py: Always Pass `--customer-id`

The Coinflow API returns a MongoDB ObjectId for the `customer` field, not the UUID shown in the Coinflow dashboard. To get the real customer UUID for rule matching and blocked-list lookups, always pass it explicitly:

```bash
python fetch_and_score.py <paymentId> --customer-id <uuid-from-webhook>
```

Without it, per-customer rules (MULTIPLE_CARD_NAMES, GENDER_SWITCH, FAILED_PATTERNS) will likely miss history because the ObjectId won't match the UUIDs in the payments CSV.

---

## Do Not Store Files You Want to Keep in payments/

`download_payments.py` writes a new `payments-{date}.csv` after each run and removes the previous file if the date has changed. It merges rather than replaces, but the old filename is still deleted once the new merged file is written. Only Coinflow payment exports should live in `payments/`.

---

## Only the First File in payments/ Is Used

Both `fraud_detection.py` and `build_blocked_list.py` auto-pick the **alphabetically first** file in `payments/`. If multiple exports are present, the rest are silently ignored. Keep at most one file in `payments/` unless passing an explicit path.

---

## IP_BLOCKED Fires INSTANT BAN but Does Not Auto-Append

`fetch_and_score.py` prints `!! INSTANT BAN !!` when IP_BLOCKED, TOKEN_BLOCKED, or EMAIL_BLOCKED fires. But only TOKEN_BLOCKED and EMAIL_BLOCKED trigger auto-append to `blocked_users.csv`. IP_BLOCKED is excluded because the IP may be shared by many legitimate users — blocking everyone on a shared IP would cause false positives.

---

## Shared IP Silently Downgrades from HIGH to LOW

If a card IP exactly matches a blocked user's IP but that IP is also used by more than `PUBLIC_IP_LEGITIMATE_USER_THRESHOLD` (default: 10) legitimate customers, the rule fires at LOW instead of HIGH. This downgrade won't be obvious in the output unless you read the `reason_summary` carefully: it will say *"shared IP — N legit users, downgraded"*.

---

## Per-Customer Rules Need Transaction History

Three rules require multiple transactions from the same customer to fire: `FAILED_PATTERNS` (Rule 13), `MULTIPLE_CARD_NAMES` (Rule 16), and `GENDER_SWITCH` (sub-flag of Rule 16). A single transaction will never trigger any of them.

In `fetch_and_score.py`, history is loaded from the local payments CSV (auto-detected from `payments/`). If the CSV is missing, stale, or doesn't contain this customer, all three rules will silently produce no results. The console will show "Loaded X prior transaction(s) for customer context" when history is found — if that line is absent, no history was loaded.

**Fix:** run `python3 download_payments.py` to refresh the local payments CSV, then re-run `fetch_and_score.py`.

---

## build_blocked_list.py Scores Customers Chronologically

When seeding `blocked_users.csv`, each blocked customer is scored only against customers who were blocked *before* them (sorted by `transaction_created_at`). This prevents self-matching (a customer can't match themselves) but means the `reason_summary` for early customers in the timeline may be weaker than for later ones who have more blocked users to match against.

---

## PAYMENT_URL_TEMPLATE Is Not Set

`fetch_and_score.py` will print a payment URL if `PAYMENT_URL_TEMPLATE` is set in `fraud_detection.py`, but it is currently an empty string. The customer URL (`CUSTOMER_URL_TEMPLATE`) works fine — only the individual payment link is missing.

---

## Output CSVs Use UTF-8 BOM

All output CSVs are written with `encoding="utf-8-sig"` (UTF-8 with BOM) so Excel opens them without encoding prompts. Other tools (Python `open()`, some Unix utilities) may see a BOM prefix (`﻿`) at the start of the file. Read them with `pd.read_csv(..., encoding="utf-8-sig")` or `encoding="utf-8"` to strip it.

---

## --threshold 0 for Debugging

The default `MIN_RISK_THRESHOLD = 5` means any transaction scoring below 5 is silently excluded from all output. When debugging why a transaction isn't appearing, run with `--threshold 0` to see everything.

---

## All Columns Are Loaded as Strings

The CSV loader sets `dtype=str` on all columns to prevent pandas from mangling leading zeros in payment IDs, ZIP codes, auth codes, and card tokens. `total_cents` and `transaction_created_at` are coerced to their proper types afterward. If you add new numeric or date columns, coerce them explicitly — don't assume pandas will infer the type correctly.

---

## Mixed tz-naive / tz-aware Timestamps Cause Sort Failures

`parse_timestamp` in `fraud_detection.py` has two parsing paths:
- Primary (Coinflow export format `"Wed Apr 22 2026 ..."`) → **tz-naive** unless explicitly localized
- Fallback (ISO / API format) → **tz-aware UTC** via `utc=True`

When a payments CSV is produced by merging a Coinflow export with API-downloaded rows (e.g. after running `download_payments.py --yesterday` on top of an existing export), the `transaction_created_at` column ends up with mixed types. Any sort or comparison on that column raises:

```
TypeError: Cannot compare tz-naive and tz-aware timestamps
```

**Fix already applied:** the primary path now calls `.tz_localize("UTC")` so both paths always return tz-aware UTC. If this error resurfaces, check whether any new timestamp-parsing code is producing tz-naive values.

## pandas Drops groupby Key After apply()

`run_rule_13()` uses `df.groupby("customer_id", group_keys=False).apply(...)`. pandas drops the `customer_id` column from the result. The code explicitly restores it afterward:
```python
if "customer_id" not in result.columns:
    result["customer_id"] = df["customer_id"]
```
If you add other `groupby().apply()` calls, you'll need to do the same.

---

## Auth Code 59 Is MEDIUM, Not HIGH

Code 59 ("Suspected Fraud") is intentionally placed in `AUTH_HIGH_RISK` (MEDIUM) rather than `AUTH_INSTANT_BLOCK` (HIGH). This is by design: it accumulates with other signals rather than triggering an instant block on its own. Don't move it to HIGH without understanding the false-positive impact.

---

## NAME_BLOCKED Rarity Depends on SSA Name Frequency Data

`NAME_BLOCKED` escalates to HIGH for rare names and de-escalates to FLAG_LOW for very common ones. This uses frequency data from the SSA baby names files. If `female_names.csv` was built from incomplete SSA data (e.g. missing recent years), some names will have `None` frequency and default to MEDIUM — neither escalated nor de-escalated.
