# Fraud Detection — Developer Reference

## What this project does

Scores payment transactions for fraud risk. Downloads payment history from Coinflow into PostgreSQL, builds a reference list of known blocked users, then scores every other transaction against 21 weighted rules. Produces two output CSVs: one with every flagged transaction, one with one row per non-blocked customer who should be blocked. Also runs a real-time webhook server that scores incoming payments, auto-blocks instant-ban rule matches via the Coinflow API, and displays results in the terminal.

## How to run

```bash
# First-time setup
python3 -m venv path/to/venv
source path/to/venv/bin/activate
pip install -r requirements.txt

# Build the female names reference (only needs to be done once, or when SSA data updates)
python3 build_female_names.py names/

# Initial DB setup + full history download (run once on a new environment)
python3 download_payments.py --all-time   # downloads to DB
python3 seed_blocked.py                   # seeds blocked_users table from payments table

# If migrating from an existing CSV export rather than downloading fresh:
python3 seed_payments.py                  # loads payments/ CSV into DB (one-time, delete after)
python3 seed_blocked.py                   # seeds blocked_users table from payments table

# Run on the latest payment export — auto-picks the first file in payments/
python3 fraud_detection.py

# Or point at a specific file
python3 fraud_detection.py payments/some-export.csv

# Lower the threshold to see more results (default: 5)
python3 fraud_detection.py --threshold 0

# Routine daily refresh (merges into existing DB — fast)
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

# Add a customer to the verified list (marks as previously reviewed)
python3 add_verified_customer.py <paymentId>
python3 add_verified_customer.py <paymentId> --note "manually reviewed 2026-04-25"

# Send a signed test webhook to the local server (for testing)
python3 send_test_webhook.py <paymentId>
python3 send_test_webhook.py <paymentId> --customer-id <uuid> --event-type "Card Payment Declined"
```

## File layout

```
fraud_detection.py       Main scoring script (batch mode)
fetch_and_score.py       Fetch a single Coinflow payment by ID, score it in real-time, auto-block on instant-ban rule matches
block_customer.py        Block a customer by ID via the Coinflow prod API
download_payments.py     Download payments from Coinflow API → PostgreSQL DB; auto-updates blocked_users
build_blocked_list.py    Seed or update blocked_users table from DB or a local payments CSV export
build_female_names.py    Preprocesses SSA baby name files → female_names.csv
add_verified_customer.py Add a customer to the verified_customers DB table by payment ID
send_test_webhook.py     Send a signed test webhook to the local server or Cloud Run (--url flag for remote)
analyze.py               Ad-hoc query workspace — `python -i analyze.py` loads payments/blocked/verified into pandas for exploration
db.py                    PostgreSQL data access layer — schema init, CRUD for payments/blocked_users/verified_customers
webhook_server.py        Real-time webhook server — scores each incoming payment, auto-blocks instant-ban matches via Coinflow API
seed_payments.py         One-time migration: load payments/ CSV into the DB (delete after use)
seed_blocked.py          One-time migration: seed blocked_users table from the payments table (delete after use)
requirements.txt         Python dependencies
blocked_users.csv        Legacy CSV — still written by build_blocked_list.py for batch scoring; DB is the live source
verified_customers.csv   Customers previously reviewed — loaded by webhook server for badge display
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
COINFLOW_VALIDATION_KEY=...                       # from Coinflow dashboard → Developers → Webhooks
DATABASE_URL=postgresql+psycopg2://user:pass@host/dbname
```

- `COINFLOW_API_KEY` — required by `fetch_and_score.py`, `download_payments.py`, `block_customer.py`, and `webhook_server.py`
- `COINFLOW_VALIDATION_KEY` — required to verify webhook signatures; if unset, signature verification is disabled
- `DATABASE_URL` — required by `webhook_server.py`, `download_payments.py`, `build_blocked_list.py`, and the seed scripts; batch scoring (`fraud_detection.py`) reads from local CSV files and does not need it

## PostgreSQL schema (`db.py`)

Three tables, created automatically by `db.init_db()` on server startup:

| Table | Primary key | Description |
|---|---|---|
| `payments` | `payment_id` | Full payment history — all fields from the Coinflow export |
| `blocked_users` | `customer_id` | Known-bad customers; mirrors `blocked_users.csv` schema |
| `verified_customers` | `customer_id` | Previously-reviewed customers; mirrors `verified_customers.csv` |

`db.py` exposes typed CRUD functions used by `webhook_server.py`, `download_payments.py`, and `build_blocked_list.py`. The batch scoring script (`fraud_detection.py`) still reads from local CSV files.

### Querying the DB from Claude Code

A read-only Postgres MCP server is wired up via `.mcp.json` at the repo root. When Claude Code starts a session in this directory it spawns [`crystaldba/postgres-mcp`](https://github.com/crystaldba/postgres-mcp) (via `uvx`, pinned to Python 3.12 because `pglast` has no wheels for 3.13+) in `--access-mode=restricted` (only `SELECT` is allowed), pointed at `${DATABASE_URL}` with the SQLAlchemy `postgresql+psycopg2:` scheme rewritten to plain `postgresql:` at launch. Use the MCP for pure SQL questions — Claude can write the query itself. Use `analyze.py` when the answer needs pandas/numpy on top of the rows. See `potential_upgrades.md` for follow-ups.

Requires `uv` on the local machine (`brew install uv`).

## blocked_users.csv / blocked_users table

The live reference used by every scoring run. One row per known-bad customer.

| Column | Description |
|---|---|
| `customer_id` | Coinflow customer UUID |
| `customer_email`, `card_email` | Email addresses |
| `card_first_name`, `card_last_name`, `full_name` | Name (`full_name` is `first last` lowercased) |
| `card_ip` | IP address at time of transaction |
| `card_city`, `card_ip_city`, `card_region`, `card_ip_zip`, `card_zip`, `card_street` | Location fields |
| `card_token`, `card_last4`, `bin_country` | Card identity fields |
| `all_card_ips` | All unique IPs used by this customer (`\|\|\|`-separated) |
| `all_card_emails` | All unique emails used by this customer (`\|\|\|`-separated) |
| `all_card_tokens` | All unique card tokens used by this customer (`\|\|\|`-separated) |
| `all_card_streets` | All unique street addresses used by this customer (`\|\|\|`-separated) |
| `all_full_names` | All unique full names used by this customer (`\|\|\|`-separated) |
| `reason_summary` | Why this customer was blocked |
| `added_at` | ISO timestamp when added to the list |
| `source` | `seeded_csv` (build_blocked_list.py) or `webhook_server` (webhook_server.py auto-detect) |

**Lifecycle:**
1. **Seed** — `python3 build_blocked_list.py` reads `customer_status == "Blocked"` rows from the payments CSV (or DB via `build_from_db()`), scores each chronologically against previously-blocked users (to capture cross-user email/token matches without self-matching), and writes `blocked_users.csv` + upserts to the DB. Falls back to `"Blocked in Coinflow"` as the reason when no rules fire.
2. **Refresh** — `python3 download_payments.py` fetches fresh data from the API, upserts into the DB (deduplicating on `paymentId`), and calls `build_blocked_list.py` automatically. Existing customer IDs in `blocked_users` are never duplicated.
3. **Real-time append** — `webhook_server.py` auto-appends new customers to `blocked_users` (DB) when any `INSTANT_BLOCK_RULES` rule fires.

## verified_customers.csv

Customers that have been manually reviewed. Being on this list is a prior-review signal — it does not mean the customer cannot commit fraud.

| Column | Source |
|---|---|
| `customer_id` | from Coinflow payment API |
| `card_first_name`, `card_last_name` | from Coinflow payment API |
| `card_email` | from Coinflow payment API |
| `note` | optional `--note` CLI flag |
| `added_at` | ISO timestamp at run time |
| `added_by_payment_id` | payment ID passed on the CLI |

Add a customer: `python3 add_verified_customer.py <paymentId>`. The webhook server loads this CSV on hourly refresh and shows a `⊕ Previously Verified` badge (in mauve) when a transaction comes in from a verified customer.

## webhook_server.py behavior

Real-time scoring server. On each incoming webhook:
1. Verifies Coinflow-Signature (skipped if `COINFLOW_VALIDATION_KEY` is unset)
2. Fetches the full payment from the Coinflow API
3. Loads customer transaction history from DB
4. Scores the payment through the same 21-rule engine as the batch script
5. Prints results to the terminal with color-coded output
6. If instant-ban rules fire: appends to `blocked_users` DB table and calls `PUT /merchant/blocked/{id}` to block in Coinflow

**Terminal output includes:**
- Payment ID, customer name + dashboard link, amount, transaction status
- Transaction history: `Txn History: 60% success  (10 transaction(s))` — color-coded (≥90% green, 70–89% blue, <70% red)
- `⊕ Previously Verified` badge (mauve) if customer is in `verified_customers.csv`
- Risk level, score, flag count
- Per-reason breakdown with color-coded severity
- `!! INSTANT BAN !!` banner when instant-ban rules fire

**INSTANT BAN rules** (`INSTANT_BLOCK_RULES` in `webhook_server.py`):

| Rule | Trigger |
|---|---|
| `TOKEN_BLOCKED` | Card token matches a blocked user |
| `EMAIL_BLOCKED` | Email exactly matches a blocked user (score == 100; fuzzy matches flag only) |
| `AUTH_CODES_INSTANT` | Auth code in `AUTH_CODE_INSTANT_BAN` set |
| `FRAUD_CODE_ZERO_ACCEPT` | Auth code 59/83 + 0% acceptance rate + ≥3 transactions |
| `MULTI_NAME_LOW_ACCEPT` | Multiple card names + <50% acceptance + ≥3 transactions |
| `IP_FRAUD_CODE_ZERO_ACCEPT` | IP matches blocked user + auth 59/83 + 0% acceptance |

When any of these fires, the server calls `_block_in_coinflow(customer_id)` which calls `PUT /merchant/blocked/{id}` via the Coinflow API. If the API call fails, a warning is printed but the server continues normally.

**State management**: All state (payment history, blocked users, verified customers) is loaded from PostgreSQL on startup via `db.load_*()` functions and refreshed hourly in a background thread.

## fetch_and_score.py behavior

Scores a single payment in real-time by fetching it from the Coinflow API and running it through the same rule engine as the batch script.

**Customer history context**: loads prior transactions for the same `customer_id` from the local payments CSV (auto-detected from `payments/`, or passed via `--payments-file`). Required for per-customer rules: `FAILED_PATTERNS`, `MULTIPLE_CARD_NAMES`, `GENDER_SWITCH`. The fetched payment is excluded from history if it already appears in the CSV.

**INSTANT BAN console output**: if any instant-ban rule fires, the result block ends with `!! INSTANT BAN !!`.

**Auto-append to blocked list**: only `TOKEN_BLOCKED` or `EMAIL_BLOCKED` (not others, not `IP_BLOCKED`) trigger automatic append to `blocked_users.csv` in `fetch_and_score.py`. Controlled by `INSTANT_BLOCK_RULES` at the top of that script.

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

**Phase 2** — scores every transaction against 21 rules. Rules produce `RuleResult` objects which are aggregated into `risk_level`, `risk_score`, `flag_count`, and `reason_summary` per transaction.

## Risk levels and weights

| Level | Default Weight | Meaning |
|---|---|---|
| `HIGH` | 100 | Definitive fraud signal — auto-flag for ban |
| `MEDIUM` | 50 | Strong signal — prioritize for manual review |
| `LOW` | 10 | Contextual signal — accumulates with others |
| `FLAG_LOW` | 5 | Weak signal — low weight |

`risk_score` = sum of weights for all triggered rules (using `RULE_WEIGHTS` overrides where set). `risk_level` = highest level triggered. `MIN_RISK_THRESHOLD = 5` controls what appears in output (set to 0 for everything).

`reason_summary` is sorted by `(risk_level, rule_weight)` descending — highest-severity, highest-weight flags first.

## The 21 rules

| Rule | Field(s) | Logic | Level |
|---|---|---|---|
| AUTH_CODES | `auth_codes` | Auth codes in `AUTH_FLAG` (LOW) or `AUTH_MID` (MEDIUM) buckets, or per-code overrides | LOW / MEDIUM |
| AUTH_CODES_INSTANT | `auth_codes` | Auth codes in `AUTH_CODE_INSTANT_BAN` set (specific high-confidence fraud codes) | HIGH |
| BIN_COUNTRY | `bin_country` | Non-US BIN → HIGH | HIGH |
| EMAIL_BLOCKED | `card_email` | Fuzzy match vs blocked users' emails; ≥95% → HIGH, 90–94% → MEDIUM; auto-block requires exact match (score == 100) | HIGH / MEDIUM |
| EMAIL_MISMATCH | `card_email`, `customer_email` | Card email ≠ customer email | LOW |
| FEMALE_NAME | `card_first_name`, `card_email`, `customer_email` | Female first name on card, or female name in card/customer email local part | MEDIUM |
| NAME_BLOCKED | `card_first_name`, `card_last_name` | Fuzzy full-name match vs blocked users; escalates/de-escalates by name rarity | HIGH / MEDIUM / FLAG_LOW |
| CAPITALIZATION | `card_first_name`, `card_last_name` | Name not in Title Case | FLAG_LOW |
| TOKEN_BLOCKED | `card_token` | Exact match vs blocked users' tokens | HIGH (weight 150) |
| IP_BLOCKED | `card_ip` | Exact match vs blocked users' IPs; shared IP downgraded if >10 legit users | HIGH / LOW |
| CITY_MISMATCH | `card_city`, `card_ip_city` | Card city ≠ IP city (with fuzzy passthrough at 80%) | LOW |
| SAME_CITY_DIFF_ZIP | `card_city`, `card_ip_city`, `card_zip`, `card_ip_zip` | Card city matches IP city but ZIPs differ | LOW |
| STREET_BLOCKED | `card_street` | Fuzzy match vs blocked users' streets ≥90%; skipped if both card ZIP and matched ZIP are known and differ | HIGH |
| FAILED_PATTERNS | `transaction_status`, `auth_codes`, `total_cents` | Per-customer history: 3+ consecutive failures, escalating amounts, large failed transactions, early-account failure clusters, mid-history failures | HIGH / MEDIUM / LOW |
| FRAUD_CODE_ZERO_ACCEPT | `auth_codes`, `transaction_status` | Auth code 59/83 present with 0% acceptance rate across ≥3 transactions | HIGH (weight 100) |
| MULTI_NAME_LOW_ACCEPT | `card_first_name`, `card_last_name`, `transaction_status` | Multiple card names used + <50% acceptance rate across ≥3 transactions | HIGH (weight 150) |
| IP_FRAUD_CODE_ZERO_ACCEPT | `card_ip`, `auth_codes`, `transaction_status` | IP matches blocked user AND customer has 0% acceptance with auth 59/83 | HIGH (weight 100) |
| GEO_RISK / GEO_RISK_IP | `card_city`, `card_ip_city` | City in risky list (fuzzy match at 85%); IP city weighted slightly higher (15 vs 10) | LOW |
| AMOUNT_FLAG | `total_cents` | 99¢ ending → LOW; non-standard amount on first transaction → LOW; >$100 → FLAG_LOW; >$200 → LOW; >$500 → MEDIUM; >$1000 → MEDIUM ("extremely large"); large FAILED >$500 → LOW | FLAG_LOW → MEDIUM |
| MULTIPLE_CARD_NAMES | `card_first_name`, `card_last_name` | Customer uses more than one distinct full name across transactions; names that are token-subsets of each other are clustered as one identity (so middle-name additions and Hispanic two-surname patterns don't fire) | HIGH (weight 150) |
| GENDER_SWITCH | `card_first_name`, `card_last_name` | Card names switch between female and male across transactions (sub-flag of MULTIPLE_CARD_NAMES) | MEDIUM |
| EMAIL_NAME_MISMATCH | `card_email`, `card_first_name`, `card_last_name` | Email local part looks name-formatted but doesn't fuzzy-match the card name at ≥75% | LOW |

## Configurable constants (top of fraud_detection.py)

All thresholds are named constants — nothing is hardcoded in rule logic.

| Constant | Default | Purpose |
|---|---|---|
| `MIN_RISK_THRESHOLD` | 5 | Min score to appear in output |
| `FUZZY_MATCH_THRESHOLD` | 90 | Single fuzzy similarity % used by all fuzzy rules (email, name, street) |
| `EMAIL_BLOCKED_HIGH_THRESHOLD` | 95 | Email fuzzy match ≥ this → HIGH; 90–94% → MEDIUM; auto-block requires score == 100 |
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
| `NAME_RARITY_RARE_THRESHOLD` | 0.0001 | First name frequency below this → escalate NAME_BLOCKED to HIGH |
| `NAME_RARITY_COMMON_THRESHOLD` | 0.001 | First name frequency above this → de-escalate NAME_BLOCKED to FLAG_LOW |

## Auth code classification

Auth codes are classified into buckets. `AUTH_CODE_INSTANT_BAN` is a separate set for codes that alone constitute an instant ban — it overlaps with `AUTH_HIGH` but also includes some `AUTH_MID`/`AUTH_LOW` codes that are high-confidence fraud signals in context.

| Bucket | Level | Examples |
|---|---|---|
| `AUTH_CODE_INSTANT_BAN` | HIGH (rule: `AUTH_CODES_INSTANT`) | 04, 07, 41, 43, 46, 62, 63, 78, 871, 872, 886 (plus 54, 72, 93, 15) |
| `AUTH_HIGH` | HIGH (rule: `AUTH_CODES`) | 04, 07, 41, 43, 46, 62, 63, 78, 83, 103, 871, 872, 886 |
| `AUTH_MID` | MEDIUM | 59, 93, 100, 870, 873, 874, 997, 998, 999, 9G, 888 |
| `AUTH_FLAG` | LOW | 01, 02, 05, 57, 58, 61, 65, 82, 97, N7 |
| `AUTH_LOW` | FLAG_LOW | 51, 54, 72 — escalate to HIGH if 3+ consecutive |
| `AUTH_IGNORE` | — | 03, 06, 10, 12, 13, 14, 15, 19, 25, 28, 91, 96, 99, 887, 889 |

Use `AUTH_CODE_RISK_OVERRIDE` and `AUTH_CODE_SCORE_OVERRIDE` dicts to tune individual codes without touching the sets.

## Performance notes

- Fuzzy matching rules (EMAIL_BLOCKED, NAME_BLOCKED, STREET_BLOCKED) use `rapidfuzz.process.extractOne` called once per row — adequate for tens of thousands of rows.
- Rule 13 (FAILED_PATTERNS) uses `groupby("customer_id").apply()` to analyze per-customer transaction history. pandas drops the groupby key from the result; it is restored explicitly after the apply.
- MULTIPLE_CARD_NAMES clusters each customer's names by token-subset relation (`_cluster_names()`) — `noel ramirez` ⊆ `noel prada ramirez` is one identity. Single-token names (e.g. just `noel`) don't subset-match. Diacritics are stripped (`josé` ≡ `jose`); hyphenated surnames stay one token. Gender switch detection still uses `groupby.transform("any")` and is gated on the cluster-based `_r16_flag`.
- All other rules use vectorized pandas operations.

## Female name detection

Run `build_female_names.py` once, pointing at the `names/` directory containing SSA baby name files (`yob1880.txt` … `yob2024.txt`). It aggregates all years, computes the female ratio per name, and writes `female_names.csv` (64,463 names at ≥70% female ratio). The main script loads this as a set for O(1) lookup. Also used for gender-switch detection in MULTIPLE_CARD_NAMES.

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

## Google Cloud deployment

The webhook server runs as a Cloud Run service named **`auto-compliance`** in project **`coinflow-slack-notifications`** (project number `447737634551`), region `us-central1`.

### Service URLs

| Resource | Value |
|---|---|
| Cloud Run service URL | `https://auto-compliance-jmdtnfwaya-uc.a.run.app` |
| Webhook endpoint | `https://auto-compliance-jmdtnfwaya-uc.a.run.app/webhook/<WEBHOOK_PATH_TOKEN>` |
| Artifact Registry image | `us-central1-docker.pkg.dev/coinflow-slack-notifications/cloud-run-source-deploy/auto-compliance` |
| Cloud SQL instance | `coinflow-slack-notifications:us-central1:fraud-db` (POSTGRES_15, db-f1-micro) |
| Cloud SQL database | `compliance`, user `webhook` |

### Secret Manager secrets

All secrets are stored in Secret Manager under project `coinflow-slack-notifications` and mounted as environment variables at runtime:

| Secret name | Maps to env var | Purpose |
|---|---|---|
| `COINFLOW_API_KEY` | `COINFLOW_API_KEY` | Coinflow REST API authentication |
| `COINFLOW_VALIDATION_KEY` | `COINFLOW_VALIDATION_KEY` | Webhook signature verification |
| `DATABASE_URL` | `DATABASE_URL` | Cloud SQL via Unix socket: `postgresql+psycopg2://webhook:<pass>@/compliance?host=/cloudsql/coinflow-slack-notifications:us-central1:fraud-db` |
| `WEBHOOK_PATH_TOKEN` | `WEBHOOK_PATH_TOKEN` | 48-char hex token embedded in the webhook URL path (replaces IAM auth — org policy blocks `allUsers`) |

### Cloud Run config

- **Min instances: 1** — keeps the server warm; avoids cold-start latency and preserves in-memory state
- **Max instances: 1** — prevents split state across instances (payment history and blocked list are in-memory)
- **ANSI colors**: automatically disabled in Cloud Run — `webhook_server.py` detects `K_SERVICE` env var (set by the runtime) and sets `COLOR_THEME = "none"`
- **Log timestamps**: Eastern time (`America/New_York`) via `ZoneInfo`

### Deploy workflow

```bash
# 1. Build and push Docker image
gcloud builds submit \
  --tag us-central1-docker.pkg.dev/coinflow-slack-notifications/cloud-run-source-deploy/auto-compliance \
  --project=coinflow-slack-notifications

# 2. Deploy new revision
gcloud run deploy auto-compliance \
  --image us-central1-docker.pkg.dev/coinflow-slack-notifications/cloud-run-source-deploy/auto-compliance:latest \
  --region=us-central1 \
  --project=coinflow-slack-notifications
```

Always run both commands from `/Users/omstachu/code/compliance` (the `main` branch worktree — Cloud Build uploads the local directory).

### View logs

```bash
# Stream live (best for active monitoring)
gcloud beta logging tail \
  "resource.type=cloud_run_revision AND resource.labels.service_name=auto-compliance" \
  --project=coinflow-slack-notifications \
  --format="value(textPayload)"

# Read recent logs (non-streaming)
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=auto-compliance" \
  --project=coinflow-slack-notifications \
  --freshness=30m \
  --format="value(textPayload)"
```

Use `gcloud beta logging tail` (not `gcloud logging tail` — the non-beta version does not exist).

### Test against Cloud Run

```bash
python send_test_webhook.py <paymentId> \
  --url https://auto-compliance-jmdtnfwaya-uc.a.run.app/webhook/<WEBHOOK_PATH_TOKEN>
```

### Log format

Every incoming webhook logs a `←` entry line before any filtering:
```
[2026-04-30 15:08:26] ← 'Card Payment Declined'  id='...'  customer='...'
```

Ignored event types (`Withdraw Pending`, `Withdraw Success`, `KYC Success`, etc.) log:
```
[2026-04-30 15:07:39] → ignored  eventType='Withdraw Success'
```

Handled events proceed to full scoring output. `HANDLED_EVENT_TYPES = {"Settled", "Card Payment Authorized", "Card Payment Declined"}`.

### Relationship to coinflow-slack-notifications service

There is a separate older Cloud Run service (`coinflow-slack-notifications`) that handles Slack notifications for the payment team. The `auto-compliance` service is independent — do not modify the older service or its Cloud Run config.
