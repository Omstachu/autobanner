# Fraud Detection — Developer Reference

## What this project does

Scores payment transactions for fraud risk. Reads a CSV export from Coinflow (the payment provider), builds a reference list of known blocked users, then scores every other transaction against 17 weighted rules. Produces two output CSVs: one with every flagged transaction, one with one row per non-blocked customer who should be blocked. Also prints risky city candidates to the console based on blocked user IP city distribution.

## How to run

```bash
# First-time setup
python3 -m venv path/to/venv
source path/to/venv/bin/activate   # or: path/to/venv/bin/python3 fraud_detection.py
pip install -r requirements.txt

# Build the female names reference (only needs to be done once, or when SSA data updates)
python3 build_female_names.py names/

# Run on the latest payment export — auto-picks the first file in payments/
python3 fraud_detection.py

# Or point at a specific file
python3 fraud_detection.py payments/some-export.csv

# Lower the threshold to see more results (default: 5)
python3 fraud_detection.py --threshold 0

# Initial full history download
python3 download_payments.py --all-time

# Routine daily refresh (merges into existing CSV — fast)
python3 download_payments.py --yesterday

# Other date range options
python3 download_payments.py --days 180
python3 download_payments.py --since 2026-01-01

# Seed blocked_users.csv from a local payments CSV (run after first download, or on a fresh export)
python3 build_blocked_list.py
python3 build_blocked_list.py payments/export.csv

# Fetch and score a single payment by ID (auto-blocks on instant-ban rules)
python3 fetch_and_score.py <paymentId>
python3 fetch_and_score.py <paymentId> --customer-id <uuid>

# Block a customer via the Coinflow API
python3 block_customer.py <customerId>
```

## File layout

```
fraud_detection.py       Main scoring script (batch mode)
fetch_and_score.py       Fetch a single Coinflow payment by ID, score it in real-time, auto-block on instant-ban rule matches
block_customer.py        Block a customer by ID via the Coinflow prod API
download_payments.py     Download payments from Coinflow API → payments/; auto-updates blocked_users.csv
build_blocked_list.py    Seed or update blocked_users.csv from a local payments CSV export
build_female_names.py    Preprocesses SSA baby name files → female_names.csv
requirements.txt         Python dependencies (pandas, rapidfuzz, tabulate, openpyxl)
blocked_users.csv        Live blocked-user reference list — seeded by build_blocked_list.py, auto-appended by fetch_and_score.py
female_names.csv         Generated — female first names with gender ratio (run build_female_names.py)
payments/                Drop input CSV exports here (script picks the first file alphabetically)
output/                  All output CSVs land here
names/                   SSA baby name files (yobYYYY.txt), used by build_female_names.py
FRAUD_DETECTION.md       Rule specification and business logic documentation
PITFALLS.md              Operational gotchas, non-obvious behaviors, and things to avoid
fraud-detection-schema.md  Field definitions and column mappings
```

## Environment setup

Create a `.env` file in the project root:

```
COINFLOW_API_KEY=your_api_key_here
COINFLOW_API_URL=https://api.coinflow.cash/api    # optional — defaults to prod
```

`COINFLOW_API_KEY` is required by `fetch_and_score.py`, `download_payments.py`, and `block_customer.py`. The batch scoring script (`fraud_detection.py`) reads from local CSV files and does not need it.

## blocked_users.csv

The live reference file used by every scoring run. One row per known-bad customer.

| Column | Description |
|---|---|
| `customer_id` | Coinflow customer UUID |
| `customer_email`, `card_email` | Email addresses |
| `card_first_name`, `card_last_name`, `full_name` | Name (`full_name` is `first last` lowercased) |
| `card_ip` | IP address at time of transaction |
| `card_city`, `card_ip_city`, `card_region`, `card_ip_zip`, `card_zip`, `card_street` | Location fields |
| `card_token`, `card_last4`, `bin_country` | Card identity fields |
| `reason_summary` | Why this customer was blocked |
| `added_at` | ISO timestamp when added to the list |
| `source` | `seeded_csv` (build_blocked_list.py) or `auto_detected` (fetch_and_score.py) |

**Lifecycle:**
1. **Seed** — `python3 build_blocked_list.py` reads `customer_status == "Blocked"` rows from the payments CSV, scores each chronologically against previously-blocked users (to capture cross-user email/token matches without self-matching), and writes `blocked_users.csv`. Falls back to `"Blocked in Coinflow"` as the reason when no rules fire.
2. **Refresh** — `python3 download_payments.py` fetches fresh data from the API, merges it into the existing payments CSV (deduplicating on `paymentId`), and calls `build_blocked_list.py` automatically. Existing customer IDs in `blocked_users.csv` are never duplicated.
3. **Real-time append** — `fetch_and_score.py` auto-appends new customers to `blocked_users.csv` when `TOKEN_BLOCKED` or `EMAIL_BLOCKED` fires (controlled by `INSTANT_BLOCK_RULES` in that script).

## fetch_and_score.py behavior

Scores a single payment in real-time by fetching it from the Coinflow API and running it through the same rule engine as the batch script.

**Customer history context**: loads prior transactions for the same `customer_id` from the local payments CSV (auto-detected from `payments/`, or passed via `--payments-file`). Required for per-customer rules: `FAILED_PATTERNS`, `MULTIPLE_CARD_NAMES`, `GENDER_SWITCH`. The fetched payment is excluded from history if it already appears in the CSV.

**INSTANT BAN console output**: if `IP_BLOCKED`, `TOKEN_BLOCKED`, or `EMAIL_BLOCKED` fires, the result block ends with:

```
──────────────────────────────────────────────────────────────────────
  !! INSTANT BAN !!
══════════════════════════════════════════════════════════════════════
```

**Auto-append to blocked list**: a subset of the above — only `TOKEN_BLOCKED` or `EMAIL_BLOCKED` (not `IP_BLOCKED`, since the IP may be shared) triggers an automatic append to `blocked_users.csv`. Controlled by `INSTANT_BLOCK_RULES = {"TOKEN_BLOCKED", "EMAIL_BLOCKED"}` at the top of `fetch_and_score.py`.

## Output files

Both files are written to `output/` with a timestamp prefix:

| File | Contents |
|---|---|
| `{ts}_{input}_all_flags.csv` | Every flagged transaction at or above `MIN_RISK_THRESHOLD` |
| `{ts}_{input}_should_block.csv` | One row per currently-Functional customer who should be blocked — shows their highest-scoring transaction |

Both are written as UTF-8 with BOM so Excel opens them correctly without encoding issues.

Key output columns:
- `total_amount` — transaction amount formatted as `$X.XX` (derived from `total_cents`)
- `matched_blocked_customer_url` — hyperlink to the blocked customer's Coinflow profile when Rule 3 (email) or Rule 6 (name) fires
- `match_explanation` — human-readable string describing what matched and at what score (e.g. `Email 94% match (a@b.com ~ x@y.com)`)
- `reason_summary` — ` | `-separated string of all triggered rule reasons, sorted by severity then rule weight descending

## Input data

The script expects a Coinflow payment provider CSV export (144 columns, dot-notation headers like `cardInfo.enhancedTxInfo.email`). It automatically renames columns to snake_case via `COLUMN_RENAME_MAP` at the top of `fraud_detection.py`.

The provider timestamp format — `Wed Apr 22 2026 00:20:44 GMT+0000 (Coordinated Universal Time)` — is parsed automatically.

All columns are loaded as strings initially, then coerced to the correct types internally (prevents pandas from mangling IDs, ZIPs, and auth codes with leading zeros).

## Two-phase architecture

**Phase 1** — filters `customer_status == "Blocked"` rows and builds a reference table of 15 identity/location fields per blocked customer. Deduplicated to one row per `customer_id` (most recent transaction kept).

**Phase 2** — scores every transaction against 17 rules. Rules produce `RuleResult` objects which are aggregated into `risk_level`, `risk_score`, `flag_count`, and `reason_summary` per transaction.

## Risk levels and weights

| Level | Default Weight | Meaning |
|---|---|---|
| `HIGH` | 100 | Definitive fraud signal — auto-flag for ban |
| `MEDIUM` | 50 | Strong signal — prioritize for manual review |
| `LOW` | 10 | Contextual signal — accumulates with others |
| `FLAG_LOW` | 5 | Weak signal — low weight |

`risk_score` = sum of weights for all triggered rules (using `RULE_WEIGHTS` overrides where set). `risk_level` = highest level triggered. `MIN_RISK_THRESHOLD = 5` controls what appears in output (set to 0 for everything).

`reason_summary` is sorted by `(risk_level, rule_weight)` descending — highest-severity, highest-weight flags first.

## The 17 rules

| Rule | Field(s) | Logic | Level |
|---|---|---|---|
| AUTH_CODES | `auth_codes` | Classifies processor auth codes per configurable lists; per-code level and score overrides supported | varies |
| BIN_COUNTRY | `bin_country` | Non-US BIN → HIGH | HIGH |
| EMAIL_BLOCKED | `card_email` | Fuzzy match vs blocked users' emails at ≥`FUZZY_MATCH_THRESHOLD` (90%) | HIGH / MEDIUM / LOW |
| EMAIL_MISMATCH | `card_email`, `customer_email` | Card email ≠ customer email | LOW |
| FEMALE_NAME | `card_first_name`, `card_email`, `customer_email` | Female first name on card, or female name in card email local part, or female name in customer email local part (checked separately) | MEDIUM |
| NAME_BLOCKED | `card_first_name`, `card_last_name` | Fuzzy full-name match vs blocked users; escalates/de-escalates by name rarity | HIGH / MEDIUM / FLAG_LOW |
| CAPITALIZATION | `card_first_name`, `card_last_name` | Name not in Title Case | FLAG_LOW |
| TOKEN_BLOCKED | `card_token` | Exact match vs blocked users' tokens | HIGH (weight 150) |
| IP_BLOCKED | `card_ip` | Exact match vs blocked users' IPs; shared IP downgraded if >10 legit users | HIGH / LOW |
| CITY_MISMATCH | `card_city`, `card_ip_city` | Card city ≠ IP city (with fuzzy passthrough at 80%) | LOW |
| SAME_CITY_DIFF_ZIP | `card_city`, `card_ip_city`, `card_zip`, `card_ip_zip` | Card city matches IP city but ZIPs differ | LOW |
| STREET_BLOCKED | `card_street` | Fuzzy match vs blocked users' streets ≥90% | HIGH |
| FAILED_PATTERNS | `transaction_status`, `auth_codes`, `total_cents` | Per-customer history: 3+ consecutive failures, escalating amounts, large failed transactions, early-account failure clusters, mid-history failures | HIGH / MEDIUM / LOW |
| GEO_RISK / GEO_RISK_IP | `card_city`, `card_ip_city` | City in risky list (fuzzy match at 85%); IP city weighted slightly higher (15 vs 10) | LOW |
| AMOUNT_FLAG | `total_cents` | 99¢ ending (probe pattern) → LOW; non-standard amount on first transaction → LOW; >$100 → FLAG_LOW; >$200 → LOW; >$500 → MEDIUM; >$1000 → MEDIUM ("extremely large"); large FAILED transaction (>$500 and status FAILED) → LOW | FLAG_LOW → MEDIUM |
| MULTIPLE_CARD_NAMES | `card_first_name`, `card_last_name` | Customer uses more than one distinct full name across transactions | HIGH (weight 150) |
| GENDER_SWITCH | `card_first_name`, `card_last_name` | Card names switch between female and male across transactions (sub-flag of Rule 16) | MEDIUM |
| EMAIL_NAME_MISMATCH | `card_email`, `card_first_name`, `card_last_name` | Email local part contains 2+ alpha tokens of 3+ characters (looks name-formatted) but none fuzzy-match the card first/last name at ≥75% | LOW |

## Configurable constants (top of fraud_detection.py)

All thresholds are named constants — nothing is hardcoded in rule logic.

| Constant | Default | Purpose |
|---|---|---|
| `MIN_RISK_THRESHOLD` | 5 | Min score to appear in output |
| `FUZZY_MATCH_THRESHOLD` | 90 | Single fuzzy similarity % used by all fuzzy rules (email, name, street) |
| `FUZZY_CITY_PASS_THRESHOLD` | 80 | City fuzzy passthrough — avoids false positives on abbreviations |
| `RISKY_CITY_FUZZY_THRESHOLD` | 85 | Fuzzy match threshold for risky city detection (catches misspellings) |
| `VALID_AMOUNTS` | [5000, 10000, 50000, 100000] | Standard price points in cents ($50/$100/$500/$1000) |
| `AMOUNT_FLAG_THRESHOLD` | 10000 | >$100 → FLAG_LOW |
| `AMOUNT_HIGH_RISK_THRESHOLD` | 20000 | >$200 → LOW |
| `AMOUNT_MAJOR_FLAG_THRESHOLD` | 50000 | >$500 → MEDIUM |
| `AMOUNT_INSTANT_BLOCK_THRESHOLD` | 100000 | >$1000 → MEDIUM ("Extremely large deposit") |
| `CONSECUTIVE_FAILURE_INSTANT_BLOCK` | 3 | Hard FAILEDs in a row before HIGH |
| `CONSECUTIVE_SOFT_FAILURE_INSTANT_BLOCK` | 3 | Soft codes (51/54/72) in a row before HIGH |
| `PUBLIC_IP_LEGITIMATE_USER_THRESHOLD` | 10 | Shared IP: legit users before downgrading to LOW |
| `RISKY_CITY_LIST` | Brooklyn, Miami, Atlanta, Queens, Bronx, The Bronx, Newark, Washington | Cities that trigger GEO_RISK / GEO_RISK_IP |
| `RISKY_STATE_LIST` | NC, AL, TN | Kept for reference — no longer used in rules |
| `AUTH_CODE_RISK_OVERRIDE` | `{}` | Per-auth-code level override: `{"43": "HIGH"}` |
| `AUTH_CODE_SCORE_OVERRIDE` | `{}` | Per-auth-code score override: `{"43": 150}` |
| `RULE_WEIGHTS` | see script | Per-rule score overrides keyed by `(rule_name, level_name)` |
| `CUSTOMER_URL_TEMPLATE` | coinflow dashboard URL | Template for `customer_url` and `matched_blocked_customer_url` columns |
| `FEMALE_NAME_GENDER_THRESHOLD` | 0.70 | Names ≥70% female-coded are flagged (used by build_female_names.py) |
| `NAME_RARITY_RARE_THRESHOLD` | 0.0001 | First name frequency below this → escalate NAME_BLOCKED to HIGH (rare name = stronger signal) |
| `NAME_RARITY_COMMON_THRESHOLD` | 0.001 | First name frequency above this → de-escalate NAME_BLOCKED to FLAG_LOW (very common name = weak signal) |

## Auth code classification

Auth codes are classified into four buckets. Code 59 (Suspected Fraud) is HIGH_RISK (MEDIUM), not HIGH, to allow accumulation with other signals before blocking.

| Bucket | Level | Examples |
|---|---|---|
| `AUTH_INSTANT_BLOCK` | HIGH | 04, 07, 41, 43, 46, 62, 63, 78, 83, 103, 871, 872, 886, 888 |
| `AUTH_HIGH_RISK` | MEDIUM | 59, 93, 100, 870, 873, 874, 997, 998, 999, 9G |
| `AUTH_FLAG` | LOW | 01, 02, 05, 57, 58, 61, 65, 82, 97, N7 |
| `AUTH_FLAG_LOW` | FLAG_LOW | 51, 54, 72 — escalate to HIGH if 3+ consecutive |
| `AUTH_IGNORE` | — | 03, 06, 10, 12, 13, 14, 15, 19, 25, 28, 91, 96, 99, 887, 889 |

Use `AUTH_CODE_RISK_OVERRIDE` and `AUTH_CODE_SCORE_OVERRIDE` dicts to tune individual codes without touching the sets.

## Performance notes

- Fuzzy matching rules (EMAIL_BLOCKED, NAME_BLOCKED, STREET_BLOCKED) use `rapidfuzz.process.extractOne` called once per row — adequate for tens of thousands of rows.
- Rule 13 (FAILED_PATTERNS) uses `groupby("customer_id").apply()` to analyze per-customer transaction history. pandas drops the groupby key from the result; it is restored explicitly after the apply.
- Rule 16 (MULTIPLE_CARD_NAMES) and gender switch detection use `groupby.transform("nunique")` / `transform("any")` — fully vectorized.
- All other rules use vectorized pandas operations.

## Female name detection

Run `build_female_names.py` once, pointing at the `names/` directory containing SSA baby name files (`yob1880.txt` … `yob2024.txt`). It aggregates all years, computes the female ratio per name, and writes `female_names.csv` (64,463 names at ≥70% female ratio). The main script loads this as a set for O(1) lookup. Also used for gender-switch detection in Rule 16.

## Adding or modifying rules

1. Add/edit the rule function (`rule_NN_name`) in Section 6 — returns `list[RuleResult]`, empty list if not triggered
2. If vectorizable, add a flag column in `_precompute_vectorized()` and read it in the rule function
3. If it requires per-customer history, integrate it into `_analyze_customer_failures()`
4. Add any new thresholds as named constants in Section 2
5. Add a `RULE_WEIGHTS` entry for the new rule name + level combination
6. Call the rule from `_apply_row_rules()` if it's a new row-level rule

## Open calibration items

- `MIN_RISK_THRESHOLD` — currently 5 (catches almost everything); raise to reduce noise once real data reviewed
- `PUBLIC_IP_LEGITIMATE_USER_THRESHOLD` — currently 10; calibrate based on real shared-IP patterns
- `RISKY_CITY_LIST` — expand based on blocked user IP city output printed at end of each run
- Failed transaction pattern thresholds — calibrate against confirmed fraud cases
- `PAYMENT_URL_TEMPLATE` — not yet set
