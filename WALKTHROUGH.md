# Fraud Detection System — Full Walkthrough

## What This System Does

This system scores payment transactions processed through Coinflow for fraud risk. It is not a black box — every decision is traceable to a specific rule with a named reason. There are two modes of operation:

- **Batch mode**: takes a full CSV export of payment history and scores every transaction, writing flagged results to output CSVs.
- **Real-time mode**: a webhook server that receives live Coinflow events, fetches each payment from the API, and scores it immediately — auto-blocking customers when the highest-severity rules fire.

The core question the system asks about every transaction is: *does this customer match the profile of someone we've already blocked, or do their own behavioral patterns look like fraud?*

---

## Project Layout

```
fraud_detection.py       The scoring engine — all 17 rules live here
fetch_and_score.py       CLI: score a single payment by ID in real-time
webhook_server.py        Flask server: receives Coinflow webhooks and auto-scores
download_payments.py     Downloads payment history from the Coinflow API
build_blocked_list.py    Seeds blocked_users.csv from a payment export
block_customer.py        Calls the Coinflow API to block a customer
send_test_webhook.py     Dev tool: sends a signed test webhook to your local server

blocked_users.csv        Live reference — all known-bad customers and why they were blocked
live_payments.csv        Webhook server's running log — all transactions seen since last start
female_names.csv         Precomputed female name set (built by build_female_names.py)
payments/                Drop Coinflow CSV exports here; scripts auto-detect the first file
output/                  Scored CSVs land here (batch mode)
names/                   Raw SSA baby name files (used once to build female_names.csv)
```

---

## How the Pieces Connect

```
Coinflow API
     │
     ├── download_payments.py ──────► payments/payments-YYYY-MM-DD.csv
     │        │                                  │
     │        └── calls ──────────────► build_blocked_list.py ──► blocked_users.csv
     │                                                                    │
     ├── fetch_and_score.py ──► fraud_detection.py ◄────────────────────┘
     │                                  ▲
     └── webhook_server.py ─────────────┘
              │  (also writes)
              └──► live_payments.csv
```

The scoring engine (`fraud_detection.py`) is a pure library — it never fetches data from the internet. Everything that calls it is responsible for loading the right data first.

---

## Reference Files

### `blocked_users.csv`

The most important file in the project. Every scored transaction is compared against this list. One row per known-bad customer, with 15 identity fields captured at the time of their most recent transaction: email addresses, name, IP, card token, city/ZIP/street, card last4, BIN country.

Key columns: `customer_id`, `card_email`, `card_first_name`, `card_last_name`, `card_ip`, `card_token`, `card_street`, `reason_summary`, `added_at`, `source`

The `source` column records how the entry got here:
- `seeded_csv` — added by `build_blocked_list.py` from a Coinflow export
- `auto_detected` — added live by `fetch_and_score.py` or `webhook_server.py` when TOKEN_BLOCKED or EMAIL_BLOCKED fired

### `payments/payments-YYYY-MM-DD.csv`

The full transaction history downloaded from Coinflow. The batch script and real-time tools use this for **per-customer rules** — detecting when the same customer uses different card names, shows escalating failure patterns, etc. Without this file those rules are blind.

Only the **alphabetically first file** in `payments/` is used. There should be exactly one file here at a time.

### `live_payments.csv`

Written by the webhook server at the project root (not in `payments/`). Every transaction the server processes is appended here as it arrives.

`live_payments.csv` serves two purposes: during normal operation, `_history_df` is the live in-memory store — every incoming webhook is appended to it immediately. `live_payments.csv` is written in parallel as a durable record. On restart, `_load_state()` merges it back into `_history_df` so those transactions aren't lost. Think of it as the write-ahead log that makes `_history_df` restartable — it is not needed for in-session history, only for recovery across restarts.

### `female_names.csv`

Built once from SSA baby name files by `build_female_names.py`. Contains 64,000+ names with a `female_ratio` column. The scoring engine loads this as a set for O(1) lookup during the FEMALE_NAME and GENDER_SWITCH rule checks.

---

## Script-by-Script Walkthrough

### `download_payments.py`

**Purpose**: Keep the local payments CSV fresh.

**What it does**:
1. Calls `GET /api/merchant/payments` with pagination (500 per page), filtering by date range
2. Flattens the nested JSON response to dot-notation column names
3. If a payments CSV already exists, merges the new data with it, deduplicating on `paymentId` (keeps last)
4. Writes `payments/payments-YYYY-MM-DD.csv` and deletes the previous file if the date changed
5. Automatically calls `build_blocked_list.py` to keep `blocked_users.csv` current

**Date range options**: `--yesterday`, `--days N`, `--since YYYY-MM-DD`, `--all-time`

**Retry logic**: 3 attempts with exponential backoff (2s, 4s) on network errors or 5xx responses. Saves a partial CSV if it fails mid-download.

**Auth note**: Requires `COINFLOW_API_KEY` in `.env`. A production key won't work against the sandbox endpoint and vice versa.

---

### `build_blocked_list.py`

**Purpose**: Seed or update `blocked_users.csv` from a payment export.

**What it does**:
1. Loads the payments CSV and filters rows where `customer_status == "Blocked"`
2. Deduplicates to one row per `customer_id`, keeping the most recent transaction
3. Scores each blocked customer **chronologically** against all previously-blocked customers to populate `reason_summary`

The chronological scoring is the key design decision here. Customer A is scored against nobody (they're first). Customer B is scored against Customer A's entry. Customer C is scored against both. This means the `reason_summary` captures cross-customer signals like "email matches a known blocked user" — but only looking backward in time, so there's no circular self-matching.

If no rules fire for a customer (e.g., their identity is totally unique), the reason falls back to `"Blocked in Coinflow"`.

**Idempotent**: existing `customer_id`s in `blocked_users.csv` are never duplicated. Safe to run repeatedly.

---

### `fraud_detection.py`

**Purpose**: The scoring engine. All 17 rules live here.

This is a library, not a standalone tool — though it has a `main()` for batch mode. Everything else imports it.

#### Two-Phase Architecture

**Phase 1 — Build the blocked user reference list** (`build_blocked_user_list`):
- Filters `customer_status == "Blocked"` rows from the input DataFrame
- Deduplicates to one row per customer (most recent transaction)
- Builds a `full_name` column (first + last, lowercased) for fuzzy matching
- Returns a clean reference DataFrame with 15 identity fields

**Phase 2 — Score all transactions** (`score_all`):
Called with the full transaction DataFrame plus the blocked-user reference. Runs four sub-steps in order:

1. **Vectorized precompute** (`_precompute_vectorized`): adds boolean flag columns for rules that can be evaluated in bulk without row-by-row logic — BIN country, email mismatch, capitalization, amount thresholds, multiple card names, gender switch, geo risk, etc.

2. **Batch fuzzy matching** (`_precompute_fuzzy`): runs `rapidfuzz.process.extractOne` once per row for Rules 3 (email), 6 (name), and 12 (street). Adds score and match-detail columns (`_r03_score`, `_r03_matched_email`, `_r06_score`, etc.).

3. **Per-customer failure analysis** (`run_rule_13`): uses `groupby("customer_id").apply()` to analyze each customer's transaction history for failure patterns — consecutive failures, escalating amounts, early-account failure clusters.

4. **Row-by-row rule application** (`_apply_row_rules` → `score_transaction`): iterates every row, calls all 17 rule functions, aggregates `RuleResult` objects into a `risk_level` / `risk_score` / `reason_summary` per transaction.

#### The Scoring Model

Each rule returns zero or more `RuleResult` objects. Each result has:
- `rule_name` — e.g., `"TOKEN_BLOCKED"`
- `risk_level` — HIGH, MEDIUM, LOW, or FLAG_LOW
- `reason` — human-readable string included verbatim in `reason_summary`
- `score_override` — optional per-result score (used by auth codes)

Scores are summed. The highest level determines `risk_level`. Reasons are sorted by `(risk_level, score)` descending — most severe first.

Default weights: HIGH=100, MEDIUM=50, LOW=10, FLAG_LOW=5. Individual rules can override these in `RULE_WEIGHTS`.

`MIN_RISK_THRESHOLD = 5` — transactions scoring below this are silently excluded from output. Set to 0 to see everything.

---

### The 17 Rules

#### Identity Match Rules (compare against blocked_users.csv)

**Rule 3 — EMAIL_BLOCKED**: fuzzy-matches the card email against every email in `blocked_users.csv` (card and customer emails). Minimum threshold: 90%. Scores: HIGH at ≥95%, MEDIUM at 90–94%. Below 90% does not fire. Auto-block in the webhook server requires an exact match (score == 100); fuzzy matches flag for manual review only. The matched blocked user's customer ID and URL are surfaced in output.

**Rule 6 — NAME_BLOCKED**: fuzzy-matches the full card name (first + last) against all blocked users' names. Same 90% threshold. Escalates to HIGH for rare names (SSA frequency < 0.01%), de-escalates to FLAG_LOW for very common names (frequency > 0.1%) — because "John Smith" matching another "John Smith" is weak evidence, but "Xiomara Delacroix" matching is very strong.

**Rule 8 — TOKEN_BLOCKED**: exact match of the card token against blocked users' tokens. Weight 150 (highest in the system). An exact card token match means the same physical card, which is definitive.

**Rule 9 — IP_BLOCKED**: exact match of the card IP. If the IP is shared by more than 10 distinct legitimate customers, downgraded from HIGH to LOW (shared IPs like university networks or VPNs are common among legitimate users).

**Rule 12 — STREET_BLOCKED**: fuzzy match of the billing street address at ≥90%, HIGH severity. Requires matching ZIP when both sides are known — prevents "123 Main St" in different cities from matching.

#### Email & Name Rules

**Rule 4 — EMAIL_MISMATCH**: fires when the card email differs from the account (customer) email. LOW severity. Only fires when customer email is non-blank — API-fetched transactions won't have it.

**Rule 5 — FEMALE_NAME**: fires MEDIUM when a female first name appears on the card. Checked three ways: the card first name itself, the local part of the card email, the local part of the customer email. Background: a disproportionate number of confirmed fraud accounts use female names.

**Rule 7 — CAPITALIZATION**: fires FLAG_LOW when a card name is not in Title Case (e.g., `john smith`, `JOHN SMITH`). Weak signal by itself, accumulates with others.

**Rule 16 — MULTIPLE_CARD_NAMES**: fires HIGH (weight 150) when the same `customer_id` has used more than one distinct full name across transactions. Reason text shows: `Multiple card names: John Smith → Mary Johnson, Bob Davis` (capped at 4 other names). Strong account-takeover signal.

**Rule 17 — EMAIL_NAME_MISMATCH**: fires LOW when the email local part looks name-formatted (two or more alpha tokens of 3+ characters, e.g. `john.smith`) but none of those tokens fuzzy-match the card first or last name at ≥75%. Catches emails that belong to a different person than the card.

**Sub-flag: GENDER_SWITCH**: part of Rule 16. Fires MEDIUM when the same customer's card names switch between female-coded and non-female-coded first names across transactions. There is no male names CSV — any name not in `female_names.csv` is treated as non-female. The rule fires when `any_female & ~all_female`: at least one name across the customer's history is female-coded and at least one is not. Gender-neutral names that happen to not be in the female list are treated as male, which is an approximation. The rule is calibrated to catch the common fraud pattern (account shared between different people of different genders) rather than eliminate all false positives.

#### Geographic Rules

**Rule 10 — CITY_MISMATCH**: card billing city doesn't match the IP geolocation city. Uses 80% fuzzy passthrough to avoid false positives on common abbreviations (e.g., "NYC" vs "New York City"). LOW.

**Rule 11 — SAME_CITY_DIFF_ZIP**: card city matches IP city but ZIPs differ. LOW. Indicates a real address/location mismatch even when the city name matches.

**Rule 14 — GEO_RISK / GEO_RISK_IP**: card city or IP city is in the configured risky city list (`RISKY_CITY_LIST`). Fuzzy-matched at 85% to catch misspellings. IP city weighted slightly higher (15 vs 10) because it's harder to spoof than the billing address.

#### Transaction Pattern Rules

**Rule 1 — AUTH_CODES**: classifies the processor response code into four tiers. HIGH for codes like 43 (Stolen Card), 41 (Lost Card), 63 (Security Violation), 888 (Address Verification Failure), etc. MEDIUM for 59 (Suspected Fraud) — intentionally not HIGH so it accumulates with other signals rather than triggering an instant block alone. LOW for codes like 05 (Do Not Honor), 82 (CVV mismatch). FLAG_LOW for 51 (Insufficient Funds), 54 (Expired Card), 72 (Account Not Yet Activated) — three in a row escalates to HIGH.

**Rule 2 — BIN_COUNTRY**: the card's Bank Identification Number (BIN) resolves to a non-US country. HIGH. A US-issued card will always have a US BIN; foreign BINs on a domestic payment are a fraud signal.

**Rule 13 — FAILED_PATTERNS**: per-customer history analysis. Fires for:
- 3+ consecutive hard failures (HIGH)
- 3+ consecutive soft failures — codes 51/54/72 (HIGH)
- Escalating amounts across failed transactions (MEDIUM)
- Failed transactions over $500 (LOW)
- 3+ failures in the first 5 transactions of a new account (MEDIUM — probing pattern)
- Failures scattered through a long transaction history (LOW)

**Rule 15 — AMOUNT_FLAG**: transaction amount signals. 99¢ ending → LOW (card probing pattern). Non-standard amount on the very first transaction → LOW. >$100 → FLAG_LOW. >$200 → LOW. >$500 → MEDIUM. >$1000 → MEDIUM ("extremely large"). >$500 and status FAILED → LOW (large failed amount is unusual).

#### Output

**Batch mode** writes two files to `output/`:
- `{ts}_{input}_all_flags.csv` — every flagged transaction above threshold, one row per transaction
- `{ts}_{input}_should_block.csv` — one row per currently-Functional customer who should be blocked, showing their worst transaction

Both are UTF-8 with BOM so Excel opens them without encoding prompts.

Key output columns: `risk_level`, `risk_score`, `flag_count`, `reason_summary`, `match_explanation` (what specifically matched a blocked user), `matched_blocked_customer_url` (link to the matched customer in Coinflow).

---

### `fetch_and_score.py`

**Purpose**: Score a single payment by ID from the command line.

**What it does**:
1. Fetches the full payment JSON from `GET /api/merchant/payments/{id}`
2. Flattens the JSON and maps field names through `COLUMN_RENAME_MAP`
3. Loads prior transactions for this customer from the local payments CSV
4. Builds a `scoring_df` = history + this transaction, then calls `fd.score_all()`
5. Filters the result to just this payment's row and prints it

**The customer ID problem**: the API returns `customer` as a MongoDB ObjectId (e.g., `69ea921d...`), not the UUID displayed in the Coinflow dashboard. The `--customer-id` flag lets you pass the real UUID from the webhook payload or dashboard. Without it, per-customer rules won't match historical transactions because the IDs won't align.

**Auto-block behavior**: if TOKEN_BLOCKED fires, or EMAIL_BLOCKED fires on an exact match (score == 100), the customer is automatically appended to `blocked_users.csv` and an `!! INSTANT BAN !!` banner is printed. EMAIL_BLOCKED at 90–99% fuzzy match prints the risk level but does not auto-block. IP_BLOCKED also prints the banner but does *not* auto-append (shared IPs cause too many false positives).

---

### `webhook_server.py`

**Purpose**: Real-time fraud scoring via Coinflow webhooks.

This is a Flask application that replaces the manual `fetch_and_score.py` workflow during live operation.

#### Startup sequence

1. Downloads the last 2 days of payments from the Coinflow API (calls `download_payments.py` as a module) — unless `--skip-download` is passed
2. Loads `blocked_users.csv`, the payments CSV from `payments/`, and merges `live_payments.csv` (durable log — recovers transactions seen since last start) into the in-memory `_history_df`
3. Starts the hourly background refresh thread
4. Starts Flask

#### Per-webhook flow (`POST /webhook`)

1. **Signature verification**: validates the `Coinflow-Signature` header using HMAC-SHA256. The signed payload is `{timestamp}.{raw_body}`. Secret is `COINFLOW_VALIDATION_KEY` from `.env`. If the env var is unset, verification is skipped (development mode).

2. **Event filtering**: only processes `Settled`, `Card Payment Authorized`, and `Card Payment Declined`. All other event types return 200/ignored.

3. **Fetch full payment**: the webhook payload only contains `data.id` and `data.customerId`. The server calls `GET /api/merchant/payments/{id}` to get all card identity fields.

4. **Under the lock**:
   - Appends the new transaction to `_history_df` (in-memory)
   - Appends to `live_payments.csv` (durable audit log), aligning to the file's existing column schema to prevent misalignment when different API responses have different fields
   - Builds `scoring_df` = this customer's history + the new transaction

5. **Score**: calls `fd.score_all()` with the current `_blocked_df` snapshot

6. **Auto-block**: if TOKEN_BLOCKED fires, or EMAIL_BLOCKED fires on an exact match (score == 100), appends the customer to `blocked_users.csv` and updates the in-memory `_blocked_df`

#### In-memory history and concurrency

The server uses a single `threading.Lock` protecting `_history_df` and `_blocked_df`. Flask runs in threaded mode — each webhook handler gets its own thread. The lock ensures that if three webhooks arrive simultaneously, each one sees the previous ones' transactions before scoring. Transaction 3 will have transactions 1 and 2 in its customer history.

#### Hourly refresh

A daemon thread (`_scheduler_thread`) sleeps for one hour, then:
1. Downloads the last 2 hours from Coinflow (`dl.download(since=now - 2h)`)
2. Reloads `blocked_users.csv` and the payments CSV from disk
3. Re-merges `live_payments.csv`
4. Acquires the lock and swaps in the new DataFrames atomically

This keeps the scoring context fresh without restarting the server.

#### Running with ngrok for production webhooks

```bash
# Terminal 1 — start server
python3 webhook_server.py --port 5001

# Terminal 2 — expose to internet
ngrok http 5001
```

Configure the ngrok URL (`https://<id>.ngrok.io/webhook`) in the Coinflow dashboard under Developers → Webhooks. Port 5000 is blocked on macOS by AirPlay Receiver — always use 5001 or higher.

---

### `block_customer.py`

**Purpose**: Directly block a customer via the Coinflow API.

Calls `PUT /api/merchant/blocked/{customerId}` with `{"status": "Blocked", "reason": "Blocked1"}`. Used when you need to block someone manually rather than waiting for the auto-block rules to fire.

```bash
python3 block_customer.py <customerId>
```

---

### `send_test_webhook.py`

**Purpose**: Dev tool for testing the webhook server locally without needing real Coinflow traffic.

Constructs a synthetic webhook payload, signs it correctly with `COINFLOW_VALIDATION_KEY`, and POSTs it to `http://localhost:{port}/webhook`. The server can't distinguish this from a real Coinflow webhook.

```bash
python3 send_test_webhook.py <paymentId>
python3 send_test_webhook.py <paymentId> --customer-id <uuid> --event-type "Card Payment Declined"
```

---

## Environment Setup

Create a `.env` file in the project root:

```
COINFLOW_API_KEY=your_key_here
COINFLOW_VALIDATION_KEY=your_webhook_secret_here   # from Coinflow dashboard → Developers → Webhooks
COINFLOW_API_URL=https://api.coinflow.cash/api      # optional, defaults to prod
```

Python dependencies: `pip install -r requirements.txt` (pandas, rapidfuzz, tabulate, openpyxl, requests, python-dotenv, flask)

First-time setup order:
1. `python3 build_female_names.py names/`
2. `python3 download_payments.py --all-time`
3. `python3 build_blocked_list.py` *(called automatically by download_payments.py — only needed manually on a fresh CSV export)*

---

## Tuning and Calibration

All thresholds are named constants at the top of `fraud_detection.py`. Nothing is hardcoded in rule logic.

| What to tune | Constant | Current default |
|---|---|---|
| Minimum score to appear in output | `MIN_RISK_THRESHOLD` | 5 |
| Fuzzy match sensitivity (email, name, street) | `FUZZY_MATCH_THRESHOLD` | 90% |
| How many shared-IP users before downgrading IP_BLOCKED | `PUBLIC_IP_LEGITIMATE_USER_THRESHOLD` | 10 |
| Cities that trigger GEO_RISK | `RISKY_CITY_LIST` | Brooklyn, Miami, Atlanta, Queens, Bronx, Newark, Washington |
| Standard price points (non-standard → flag) | `VALID_AMOUNTS` | $50, $100, $500, $1000 |
| Amount tiers | `AMOUNT_*_THRESHOLD` | $100/$200/$500/$1000 |
| Consecutive failure trigger | `CONSECUTIVE_FAILURE_INSTANT_BLOCK` | 3 |
| Per-rule score override | `RULE_WEIGHTS` | see script |
| Per-auth-code risk/score override | `AUTH_CODE_RISK_OVERRIDE` / `AUTH_CODE_SCORE_OVERRIDE` | empty |

**Debugging low output**: run with `--threshold 0` to see every transaction regardless of score. Transactions below threshold 5 are silently excluded by default.

**Expanding risky cities**: after each batch run, the script prints candidate cities based on the IP city distribution of blocked users. Add high-count cities to `RISKY_CITY_LIST`.

---

## Key Design Decisions and Tradeoffs

**Why score blocked customers against each other chronologically in `build_blocked_list.py`?** Because a fraudster's `reason_summary` should explain *why* they were blocked, not just "they were blocked." Scoring them against prior blocked users captures cross-account signals like shared tokens or emails. The chronological order prevents a customer from being their own match.

**Why is auth code 59 (Suspected Fraud) MEDIUM instead of HIGH?** By design. Code 59 is issued by the processor and is sometimes triggered by unusual-but-legitimate activity. Placing it at MEDIUM means it accumulates with other signals (e.g., female name + risky city + 59 = MEDIUM+MEDIUM+LOW = score 110, approaching HIGH territory) rather than instantly blocking on its own.

**Why is IP_BLOCKED excluded from auto-append to blocked_users.csv?** IPs are shared. Blocking a customer because their IP was used by a fraudster would block legitimate users at coffee shops, shared offices, and mobile carriers. TOKEN_BLOCKED and EMAIL_BLOCKED are more reliable identity signals.

**Why does the webhook server not modify `payments/`?** To keep the two systems cleanly separated. `payments/` is managed by `download_payments.py`, which merges and deduplicates on its own schedule. The webhook server writes its live transactions to `live_payments.csv` at the root, which is then merged back into history on restart. This prevents the auto-detection logic (alphabetically first file in `payments/`) from picking up live data as if it were a full export.

**Why `dtype=str` when loading CSVs?** Pandas will otherwise mangle leading zeros in payment IDs, ZIP codes, auth codes, and card tokens. Everything is loaded as strings and coerced to the correct types explicitly afterward.

---

## Moving to Production: Backend / Backoffice Integration

The current system runs entirely on one machine with flat files. Moving it into a real backend requires replacing the storage layer, exposing the scoring engine as a service, and wiring the results into a review UI. The scoring logic itself (`fraud_detection.py`) doesn't need to change — only the infrastructure around it.

### Current State vs. Production Target

| Concern | Local (now) | Production |
|---|---|---|
| Blocked user store | `blocked_users.csv` | Database table |
| Payment history | `payments/*.csv` | Database table (or query Coinflow API directly) |
| Webhook receiver | Flask on localhost + ngrok | Deployed service with stable URL |
| Scoring trigger | Webhook + manual CLI | Webhook (auto) + backoffice API call (on demand) |
| Scheduling | Hourly thread inside Flask process | Dedicated cron job or task queue |
| Review interface | Console output | Backoffice UI with a fraud review queue |

---

### Step 1: Replace CSV Storage with a Database

The two CSVs that need to become database tables are `blocked_users.csv` and the payments history.

**`blocked_users` table** — the most critical. Currently every rule lookup does an in-memory scan of this file. A database gives you indexed lookups and eliminates the file-lock risk.

Minimum schema:
```sql
CREATE TABLE blocked_users (
    id              SERIAL PRIMARY KEY,
    customer_id     TEXT NOT NULL UNIQUE,
    customer_email  TEXT,
    card_email      TEXT,
    card_first_name TEXT,
    card_last_name  TEXT,
    full_name       TEXT,          -- first last, lowercased, for fuzzy queries
    card_ip         TEXT,
    card_token      TEXT,
    card_street     TEXT,
    card_city       TEXT,
    card_ip_city    TEXT,
    card_region     TEXT,
    card_zip        TEXT,
    card_ip_zip     TEXT,
    card_last4      TEXT,
    bin_country     TEXT,
    reason_summary  TEXT,
    added_at        TIMESTAMPTZ DEFAULT NOW(),
    source          TEXT         -- 'seeded_csv' | 'auto_detected' | 'manual'
);
CREATE INDEX ON blocked_users (card_token);
CREATE INDEX ON blocked_users (card_ip);
CREATE INDEX ON blocked_users (card_email);
```

**`payments` table** — used by per-customer rules (MULTIPLE_CARD_NAMES, FAILED_PATTERNS, GENDER_SWITCH). You already have this data in Coinflow — the local CSV is just a cached copy. In production, this table can be populated by your existing download job and live webhook inserts.

**Migration path**:
1. Keep the CSV-based scoring engine working as-is while you build the DB layer
2. Add a thin adapter that reads from the DB and returns a pandas DataFrame in the same shape the engine expects — the engine doesn't care where the DataFrame came from
3. Update `webhook_server.py` to write to the DB instead of (or in addition to) the CSVs
4. Once validated, remove the CSV-based path

---

### Step 2: Deploy the Webhook Server as a Proper Service

The Flask app in `webhook_server.py` is already production-ready in terms of logic. What it needs:

**Containerize it**:
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "webhook_server.py", "--port", "8080", "--skip-download"]
```

**Recommended deployment options**:
- **Simple**: a single EC2 instance or VPS (DigitalOcean Droplet, Render, Railway) with nginx proxying to the Flask process managed by gunicorn
- **Serverless**: AWS Lambda + API Gateway — suitable if webhook volume is low; the stateless scoring path works fine, but the in-memory `_history_df` won't persist between invocations (requires DB-backed history)
- **Container**: ECS, Cloud Run, or Fly.io — easiest path if you're already containerizing your backend

**Gunicorn instead of Flask dev server**:
```bash
gunicorn -w 1 -b 0.0.0.0:8080 "webhook_server:app"
```
Keep `-w 1` (single worker) — the in-memory `_history_df` and `_blocked_df` are process-level state and won't be shared across workers. If you need multiple workers, the state must be in a database.

**Register the URL with Coinflow**:
In the Coinflow dashboard → Developers → Webhooks, set the URL to your deployed endpoint (e.g., `https://api.yourcompany.com/webhooks/coinflow`). Replace the ngrok URL.

---

### Step 3: Expose a Scoring API for the Backoffice

Right now the only way to trigger scoring is via webhook or CLI. Your backoffice will want to be able to score any transaction on demand — e.g., when an analyst opens a payment to review it.

Add these endpoints to `webhook_server.py` (or a separate service):

```
POST /score
  Body: { "paymentId": "...", "customerId": "..." }
  Returns: risk_level, risk_score, flag_count, reason_summary, rules_triggered

GET  /blocked/{customerId}
  Returns: whether the customer is in blocked_users, and why

POST /blocked/{customerId}
  Manually block a customer (calls block_customer.py logic + appends to blocked list)

DELETE /blocked/{customerId}
  Remove a customer from the blocked list (unblock)

POST /reload
  Trigger an immediate state reload without restarting the server
  (Useful after manual edits to blocked_users.csv or a bulk import)

GET  /health
  Returns service status, last refresh time, history row count, blocked user count
```

The `POST /score` endpoint would run the same `_fetch_payment` → `_payment_to_df` → `fd.score_all()` pipeline that the webhook handler uses, but return JSON instead of printing to console.

---

### Step 4: Backoffice Fraud Review Queue

With the scoring API in place, the backoffice integration looks like this:

**On every transaction (via webhook)**:
1. Coinflow fires `POST /webhook`
2. Server scores the payment and stores the result alongside the transaction
3. If `risk_level == "HIGH"`, create a review queue entry flagged as urgent
4. If `risk_level == "MEDIUM"`, create a review queue entry for later review
5. If TOKEN_BLOCKED fires, or EMAIL_BLOCKED fires on an exact match (score == 100), auto-block immediately and log it

**Backoffice review UI**:
- Table view: payment ID, customer, amount, risk level, score, top reason, date — sortable by score
- Detail view: full `reason_summary` breakdown, link to Coinflow customer profile, transaction history
- Actions: Block customer (calls `POST /blocked/{id}`), Dismiss flag (marks as reviewed/false positive)
- Feedback loop: dismissed flags could feed back into calibration — if a HIGH-scoring transaction is consistently dismissed by analysts, the relevant rule weights may need tuning

**Data flow with the database**:
```
Coinflow
  └── POST /webhook
        ├── _fetch_payment()
        ├── fd.score_all()
        ├── INSERT INTO transactions (payment_id, customer_id, risk_level, risk_score, reason_summary, ...)
        ├── if instant-ban: INSERT INTO blocked_users, PATCH Coinflow /merchant/blocked/{id}
        └── if HIGH/MEDIUM: INSERT INTO fraud_review_queue (payment_id, created_at, status='pending')

Backoffice
  └── GET /fraud/queue  →  SELECT * FROM fraud_review_queue WHERE status='pending' ORDER BY risk_score DESC
  └── GET /fraud/{id}   →  JOIN transactions + blocked_users + Coinflow customer URL
  └── POST /fraud/{id}/block    →  POST /blocked/{customerId}
  └── POST /fraud/{id}/dismiss  →  UPDATE fraud_review_queue SET status='dismissed'
```

---

### Step 5: Replace the Hourly Thread with a Proper Scheduler

The current hourly refresh runs as a daemon thread inside the Flask process. In production this should be a separate job that runs independently of the web server:

- **Cron** (simplest): `0 * * * * cd /app && python download_payments.py --days 1`
- **AWS EventBridge**: trigger a Lambda or ECS task hourly
- **Celery beat**: if you're already using Celery for background tasks
- **pg_cron**: if you want the download job to be database-triggered

The `POST /reload` endpoint (mentioned above) then lets the cron job signal the web server to pick up fresh data without restarting.

---

### Summary: Minimal Production Path

If you want to get to production as quickly as possible without a full database migration:

1. **Containerize**: build the Docker image (Dockerfile + `gunicorn -w 1 -b 0.0.0.0:5000 webhook_server:app`). Keep `-w 1` — all state is process-local; multiple workers would have diverging `_history_df`.

2. **Persistent storage**: mount a volume at `/data`; point `BLOCKED_LIST_PATH`, `LIVE_PAYMENTS_PATH`, and `payments/` at it. Without persistence, every redeploy loses history and blocked users.

3. **Deploy**: Railway, Render, or Fly.io all support single-process persistent containers with minimal config. Set `COINFLOW_API_KEY` and `COINFLOW_VALIDATION_KEY` as environment secrets.

4. **Wire webhook**: in Coinflow dashboard → Developers → Webhooks, set URL to `https://your-domain/webhook`. The signature verification (`COINFLOW_VALIDATION_KEY`) is what prevents spoofed webhooks.

5. **Daily refresh**: add a scheduled task (`download_payments.py --yesterday`) on the same server. This keeps `blocked_users.csv` and the payments CSV fresh. The webhook server's hourly background refresh already covers intra-day gaps — the daily job just ensures a clean merge after the day rolls over.

6. **Startup refresh**: already handled — the server calls `dl.download(since=2 days ago)` on startup automatically unless `--skip-download` is passed. No manual step needed.

7. **Observability**: Flask logs to stdout/stderr, which container platforms forward to their log aggregator automatically. To get fraud signals into a Slack channel or PagerDuty, add a `requests.post` to a Slack webhook URL inside `_print_result()` when `risk_level == "HIGH"`.

**Key constraint**: the single-process requirement is the biggest architectural limit. If you later need horizontal scaling or zero-downtime deploys, the state needs to move to a shared store (Redis for sets, PostgreSQL for history). That's a real rewrite but not urgent at current volume.
