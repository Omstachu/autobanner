"""
Fraud detection scoring script.

Usage:
    python fraud_detection.py [input_file] [--threshold N]

Phase 1: Build a blocked-user reference list from the input data.
Phase 2: Score every transaction against 17 weighted rules and write results.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from enum import IntEnum
from pathlib import Path
from typing import Optional

import pandas as pd
from rapidfuzz import fuzz, process as fuzz_process
from tabulate import tabulate

# ── Section 2: Configuration Constants ──────────────────────────────────────

# Risk level default weights
WEIGHT_HIGH     = 100
WEIGHT_MEDIUM   = 50
WEIGHT_LOW      = 10
WEIGHT_FLAG_LOW = 5

# Minimum risk score to include in output (0 = include all scored transactions)
MIN_RISK_THRESHOLD = 5

# Fuzzy match similarity threshold — all fuzzy rules use this single threshold
FUZZY_MATCH_THRESHOLD = 90

# EMAIL_BLOCKED level split: ≥ this → HIGH risk level; 90–94% → MEDIUM (review only)
# Auto-block (webhook_server.py) requires exact match (score == 100), not just HIGH level
EMAIL_BLOCKED_HIGH_THRESHOLD = 95

# City mismatch: fuzzy passthrough to avoid false positives on abbreviations
FUZZY_CITY_PASS_THRESHOLD = 80

# Amount thresholds (in cents: $100 = 10000)
VALID_AMOUNTS                  = [5000, 10000, 50000, 100000]
AMOUNT_FLAG_THRESHOLD          = 10000   # > $100 → FLAG_LOW
AMOUNT_HIGH_RISK_THRESHOLD     = 20000   # > $200 → LOW
AMOUNT_MAJOR_FLAG_THRESHOLD    = 50000   # > $500 → MEDIUM
AMOUNT_INSTANT_BLOCK_THRESHOLD = 100000  # > $1000 → extremely large (MEDIUM)

# Consecutive failure thresholds
CONSECUTIVE_FAILURE_INSTANT_BLOCK      = 3   # hard FAILEDs in a row
CONSECUTIVE_SOFT_FAILURE_INSTANT_BLOCK = 3   # auth codes 51/54/72 in a row

# How many distinct legitimate (non-blocked) users must share an IP before
# downgrading HIGH → LOW (TBD during calibration)
PUBLIC_IP_LEGITIMATE_USER_THRESHOLD = 10

# Geographic risk — cities only (states are no longer checked)
RISKY_CITY_LIST            = ["Brooklyn", "Miami", "Atlanta", "Queens", "Bronx", "The Bronx", "Newark", "Washington"]
RISKY_CITY_FUZZY_THRESHOLD = 85   # catch misspellings like "Brookly" → Brooklyn
RISKY_STATE_LIST           = ["NC", "AL", "TN", "NY"]   # kept for reference; no longer used in rules

# Auth code classifications (leading zeros preserved as strings)
AUTH_HIGH = {
    "04", "07", "41", "43", "46", "62", "63",
    "78", "83", "103", "871", "872", "886",
}
AUTH_MID = {
    "59", "93", "873", "870", "997", "998", "9G", "100", "874", "999", "888",
}
AUTH_FLAG = {
    "01", "02", "05", "57", "58", "61", "65", "82", "97", "N7",
}
AUTH_LOW = {"51", "54", "72"}   # escalate to HIGH if 3+ consecutive
AUTH_IGNORE = {
    "03", "06", "10", "12", "13", "14", "19",
    "25", "28", "91", "96", "887", "889", "99",
}

# Codes that trigger auto-append to blocked_users (same pipeline as TOKEN_BLOCKED/EMAIL_BLOCKED)
AUTH_CODE_INSTANT_BAN = {
    "04", "07", "41", "43", "46", "62", "63", "78", "871", "872", "886",  # AUTH_HIGH
    "54", "72",   # AUTH_LOW
    "93",         # AUTH_MID
    "15",         # was AUTH_IGNORE — No Such Issuer
}

# Per-auth-code risk level override — takes precedence over AUTH_* set membership.
# Keys are auth code strings; values are "HIGH"|"MEDIUM"|"LOW"|"FLAG_LOW".
AUTH_CODE_RISK_OVERRIDE: dict = {
    # "43": "HIGH",   # example: keep Stolen Card at max
}

# Per-auth-code score override — takes precedence over RULE_WEIGHTS for that specific code.
AUTH_CODE_SCORE_OVERRIDE: dict = {
    # "43": 150,   # example: give Stolen Card a heavier score
}

# Auth code human-readable titles (for reason_summary)
AUTH_CODE_TITLES = {
    "04": "Pickup Card",
    "07": "Pick Up Card, Special Condition",
    "41": "Lost Card, Pick Up",
    "43": "Stolen Card, Pick Up",
    "46": "Account Closed",
    "59": "Suspected Fraud",
    "62": "Card Not Activated",
    "63": "Security Violation",
    "78": "Blocked Account",
    "83": "Fraud/Security",
    "103": "Fraud Suspicion",
    "871": "Payment Method Blocked",
    "872": "Payment Method in Use (linked to another account)",
    "886": "Country Not Supported",
    "888": "Address Verification Failure",
    "93": "Violation, Cannot Complete",
    "873": "Name Verification Failed",
    "870": "3DS Verification Failed",
    "997": "User Failed 3DS Challenge",
    "998": "3DS Rejected",
    "9G": "Transaction Frequency Limit Exceeded",
    "100": "Visa 30 Day Failure Limit",
    "874": "Daily Purchase Limit Reached",
    "999": "Failed Chargeback Protection Checks",
    "01": "Refer to Issuer",
    "02": "Refer to Issuer, Special Condition",
    "05": "Do Not Honor",
    "57": "Transaction Not Permitted",
    "58": "Transaction Not Permitted",
    "61": "Exceeds Withdrawal Limit",
    "65": "Activity Limit Exceeded",
    "82": "CVV Mismatch",
    "97": "CVV Mismatch",
    "N7": "CVV Mismatch",
    "15": "No Such Issuer",
    "51": "Insufficient Funds",
    "54": "Expired Card",
    "72": "Account Not Yet Activated",
}

# Per-rule score overrides — keys are (rule_name, risk_level_name).
# If a key is absent, falls back to the level default (WEIGHT_* constants above).
# Edit values here to tune individual rules without touching rule logic.
# Rules at the level default (HIGH=100, MEDIUM=50, LOW=10, FLAG_LOW=5) are listed explicitly
# so they can be tuned per-rule without changing the global defaults. Weights above 100 mean
# the signal is strong enough to dominate the score even without corroboration from other rules.
RULE_WEIGHTS: dict = {
    # Auth code passthrough — weights mirror level defaults; listed so individual codes can be
    # overridden via AUTH_CODE_SCORE_OVERRIDE without raising the level defaults for everything
    ("AUTH_CODES",          "HIGH"):     100,
    ("AUTH_CODES",          "MEDIUM"):   50,
    ("AUTH_CODES",          "LOW"):      10,
    ("AUTH_CODES",          "FLAG_LOW"): 5,
    ("AUTH_CODES_INSTANT",  "HIGH"):     100,
    ("AUTH_CODES_INSTANT",  "MEDIUM"):   50,
    ("AUTH_CODES_INSTANT",  "LOW"):      10,
    ("AUTH_CODES_INSTANT",  "FLAG_LOW"): 5,

    # Identity match against blocked list
    ("TOKEN_BLOCKED",       "HIGH"):     150,  # card token is globally unique — a match is near-certain fraud
    ("BIN_COUNTRY",         "HIGH"):     100,
    ("EMAIL_BLOCKED",       "HIGH"):     100,  # ≥95% fuzzy match; auto-block requires score == 100
    ("EMAIL_BLOCKED",       "MEDIUM"):   50,   # 90–94% fuzzy match — needs corroboration
    ("EMAIL_BLOCKED",       "LOW"):      10,
    ("NAME_BLOCKED",        "HIGH"):     100,  # rare name — uniqueness raises confidence
    ("NAME_BLOCKED",        "MEDIUM"):   50,   # common or ambiguous name match
    ("NAME_BLOCKED",        "FLAG_LOW"): 5,    # very common name (e.g. Smith) — weak on its own
    ("STREET_BLOCKED",      "HIGH"):     100,
    ("IP_BLOCKED",          "HIGH"):     100,
    ("IP_BLOCKED",          "LOW"):      10,   # downgraded when IP is shared by >10 legitimate users

    # Behavioral / transaction pattern signals
    ("FAILED_PATTERNS",     "HIGH"):     100,  # 3+ consecutive hard failures or clear escalation
    ("FAILED_PATTERNS",     "MEDIUM"):   50,
    ("FAILED_PATTERNS",     "LOW"):      10,

    # Account-structure signals
    ("MULTIPLE_CARD_NAMES",       "HIGH"):   150,  # multiple identities on one account — very hard to have legitimately
    ("GENDER_SWITCH",             "MEDIUM"): 50,   # sub-signal of MULTIPLE_CARD_NAMES; weaker in isolation
    ("FRAUD_CODE_ZERO_ACCEPT",    "HIGH"):   100,  # 59/83 + 0% acceptance rate + 3+ transactions
    ("MULTI_NAME_LOW_ACCEPT",     "HIGH"):   150,  # multiple names + <50% acceptance + 2+ transactions
    ("IP_FRAUD_CODE_ZERO_ACCEPT", "HIGH"):   100,  # IP match + 59/83 + 0% acceptance
    ("FEMALE_NAME",               "MEDIUM"): 50,

    # Mismatch / anomaly signals — weak alone, meaningful when stacked
    ("EMAIL_MISMATCH",      "LOW"):      10,
    ("EMAIL_NAME_MISMATCH", "LOW"):      10,
    ("CITY_MISMATCH",       "LOW"):      10,
    ("SAME_CITY_DIFF_ZIP",  "LOW"):      10,
    ("GEO_RISK_IP",         "LOW"):      15,   # IP city is harder to spoof than a typed card city
    ("GEO_RISK",            "LOW"):      10,

    # Amount anomalies
    ("AMOUNT_FLAG",         "MEDIUM"):   50,
    ("AMOUNT_FLAG",         "LOW"):      10,
    ("AMOUNT_FLAG",         "FLAG_LOW"): 5,

    # Formatting — near-worthless alone; only relevant when stacked with other signals
    ("CAPITALIZATION",      "FLAG_LOW"): 5,
}

# Name rarity thresholds (fraction of US population from SSA data)
NAME_RARITY_COMMON_THRESHOLD = 0.001    # above → "common", de-escalate to FLAG_LOW
NAME_RARITY_RARE_THRESHOLD   = 0.0001   # below → "rare", escalate to HIGH

# Female name detection
FEMALE_NAME_GENDER_THRESHOLD = 0.70     # used by build_female_names.py
FEMALE_NAMES_CSV_PATH        = "female_names.csv"   # produced by build_female_names.py

# Output hyperlinks (set True to wrap IDs in Excel =HYPERLINK(...) formula)
HYPERLINK_OUTPUT      = False
PAYMENT_URL_TEMPLATE  = ""   # Not yet available
CUSTOMER_URL_TEMPLATE = "https://merchant.coinflow.cash/purchases?search={}"

# Name particles that are not expected to be title-cased
_NAME_PARTICLES = {"van", "de", "del", "von", "di", "la", "le", "da", "den", "der"}

# Mapping from provider CSV column names → snake_case nicknames used throughout this script
COLUMN_RENAME_MAP = {
    "cardInfo.authCode":                          "auth_codes",
    "cardInfo.cardType":                          "card_type",
    "cardInfo.enhancedTxInfo.binLocation.bankName":    "bank_name",
    "cardInfo.enhancedTxInfo.binLocation.cardName":    "card_product_name",
    "cardInfo.enhancedTxInfo.binLocation.cardSegment": "card_segment",
    "cardInfo.enhancedTxInfo.binLocation.cardType":    "card_credit_debit",
    "cardInfo.enhancedTxInfo.binLocation.country":     "bin_country",
    "cardInfo.enhancedTxInfo.city":               "card_city",
    "cardInfo.enhancedTxInfo.country":            "card_country",
    "cardInfo.enhancedTxInfo.cvvResponseCode":    "cvv_response",
    "cardInfo.enhancedTxInfo.email":              "card_email",
    "cardInfo.enhancedTxInfo.firstName":          "card_first_name",
    "cardInfo.enhancedTxInfo.ip":                 "card_ip",
    "cardInfo.enhancedTxInfo.ipLocation.city":    "card_ip_city",
    "cardInfo.enhancedTxInfo.ipLocation.region":  "card_region",
    "cardInfo.enhancedTxInfo.ipLocation.zip":     "card_ip_zip",
    "cardInfo.enhancedTxInfo.lastName":           "card_last_name",
    "cardInfo.enhancedTxInfo.state":              "card_state",
    "cardInfo.enhancedTxInfo.streetAddress":      "card_street",
    "cardInfo.enhancedTxInfo.zip":                "card_zip",
    "cardInfo.last4":                             "card_last4",
    "cardInfo.status":                            "transaction_status",
    "cardInfo.storedTransactionType":             "transaction_type",
    "cardInfo.token":                             "card_token",
    "chargebackProtectionDecision":               "chargeback_decision",
    "createdAt":                                  "transaction_created_at",
    "customer.availability.status":               "customer_status",
    "customer.customerId":                        "customer_id",
    "customer.email":                             "customer_email",
    "error":                                      "error_message",
    "liabilityOwner":                             "liability_owner",
    "paymentId":                                  "payment_id",
    "totals.total.cents":                         "total_cents",
}

# ── Section 3: Data Structures ───────────────────────────────────────────────

class RiskLevel(IntEnum):
    FLAG_LOW = 1
    LOW      = 2
    MEDIUM   = 3
    HIGH     = 4

    @property
    def weight(self) -> int:
        return {1: WEIGHT_FLAG_LOW, 2: WEIGHT_LOW,
                3: WEIGHT_MEDIUM,   4: WEIGHT_HIGH}[self.value]


@dataclass
class RuleResult:
    rule_name:     str
    risk_level:    RiskLevel
    reason:        str           # human-readable, included in reason_summary
    score_override: Optional[int] = None  # if set, uses this instead of RULE_WEIGHTS


# ── Section 4: Helper Utilities ──────────────────────────────────────────────

_TS_PAREN_RE = re.compile(r'\s*\(.*\)$')

# Map string level name → RiskLevel (used by AUTH_CODE_RISK_OVERRIDE)
_LEVEL_MAP = {
    "HIGH":     RiskLevel.HIGH,
    "MEDIUM":   RiskLevel.MEDIUM,
    "LOW":      RiskLevel.LOW,
    "FLAG_LOW": RiskLevel.FLAG_LOW,
}


def parse_timestamp(ts: str) -> Optional[pd.Timestamp]:
    """Parse 'Wed Apr 22 2026 00:20:44 GMT+0000 (Coordinated Universal Time)'."""
    if not ts or pd.isna(ts):
        return pd.NaT
    cleaned = _TS_PAREN_RE.sub("", str(ts).strip())
    try:
        return pd.to_datetime(cleaned, format="%a %b %d %Y %H:%M:%S GMT+0000").tz_localize("UTC")
    except Exception:
        try:
            return pd.to_datetime(cleaned, utc=True)
        except Exception:
            return pd.NaT


def load_female_names() -> set:
    """Load female names from CSV produced by build_female_names.py."""
    p = Path(FEMALE_NAMES_CSV_PATH)
    if not p.exists():
        print(
            f"Warning: {FEMALE_NAMES_CSV_PATH!r} not found. "
            "Female name rule will not fire. Run build_female_names.py first.",
            file=sys.stderr,
        )
        return set()
    df = pd.read_csv(p, usecols=["name"])
    return set(df["name"].str.lower().dropna())


def load_name_frequency() -> dict:
    """
    Build first-name → frequency dict from female_names.csv.
    The frequency here is female_ratio — used only for rough rarity classification in Rule 6.
    """
    p = Path(FEMALE_NAMES_CSV_PATH)
    if not p.exists():
        return {}
    df = pd.read_csv(p)
    if "female_ratio" not in df.columns:
        return {}
    return dict(zip(df["name"].str.lower(), df["female_ratio"]))


def build_ip_usage_map(df: pd.DataFrame) -> dict:
    """Count distinct legitimate (non-blocked) customer_id per IP address."""
    legit = df[df["customer_status"].str.strip() != "Blocked"]
    return (
        legit.groupby("card_ip")["customer_id"]
        .nunique()
        .to_dict()
    )


def _norm_email(s: str) -> str:
    return str(s).strip().lower() if s and not pd.isna(s) else ""


def _norm_str(s: str) -> str:
    return str(s).strip() if s and not pd.isna(s) else ""


def _email_local(email: str) -> str:
    """Return the local part (before @) of an email address."""
    e = _norm_email(email)
    return e.split("@")[0] if "@" in e else e


def _parse_auth_codes(raw: str) -> list:
    """Split a potentially multi-valued auth_codes field into a list of codes."""
    if not raw or pd.isna(raw):
        return []
    for sep in [",", "|", ";"]:
        if sep in str(raw):
            return [c.strip() for c in str(raw).split(sep) if c.strip()]
    return [str(raw).strip()]


def _is_properly_capitalized(name: str) -> bool:
    """Return True if each token is either a known particle or starts with uppercase."""
    if not name or pd.isna(name):
        return True
    tokens = str(name).strip().split()
    if not tokens:
        return True
    for token in tokens:
        clean = token.strip("-")
        if clean.lower() in _NAME_PARTICLES:
            continue
        if not clean or not clean[0].isupper():
            return False
    return True


# ── Section 5: Phase 1 — Blocked User List ───────────────────────────────────

_BLOCKED_FIELDS = [
    "customer_id", "customer_email", "card_email",
    "card_first_name", "card_last_name", "card_ip",
    "card_city", "card_ip_city", "card_region", "card_ip_zip",
    "card_zip", "card_street", "card_token", "card_last4", "bin_country",
]


def build_blocked_user_list(df: pd.DataFrame) -> pd.DataFrame:
    """Filter blocked customers and build the reference table."""
    blocked = df[df["customer_status"].str.strip() == "Blocked"].copy()
    if blocked.empty:
        print("Warning: No blocked users found in input data.", file=sys.stderr)
        return pd.DataFrame(columns=_BLOCKED_FIELDS + ["full_name"])

    available = [f for f in _BLOCKED_FIELDS if f in blocked.columns]
    blocked = blocked[available].copy()

    if "transaction_created_at" in df.columns:
        blocked["_ts"] = df.loc[blocked.index, "transaction_created_at"]
        blocked = blocked.sort_values("_ts", ascending=False)
        blocked = blocked.drop_duplicates(subset="customer_id", keep="first")
        blocked = blocked.drop(columns=["_ts"])
    else:
        blocked = blocked.drop_duplicates(subset="customer_id", keep="first")

    first = blocked.get("card_first_name", pd.Series(dtype=str)).fillna("")
    last  = blocked.get("card_last_name",  pd.Series(dtype=str)).fillna("")
    blocked["full_name"] = (first + " " + last).str.strip().str.lower()

    blocked = blocked.reset_index(drop=True)
    print(f"  Blocked user reference list: {len(blocked):,} unique customers")
    return blocked


def _build_lookup_structures(blocked_df: pd.DataFrame) -> dict:
    """Pre-compute sets and lists used by rule functions."""
    ctx: dict = {}
    ctx["blocked_tokens"] = set(blocked_df.get("card_token", pd.Series()).dropna().str.strip())
    ctx["blocked_ips"]    = set(blocked_df.get("card_ip",    pd.Series()).dropna().str.strip())

    emails = pd.concat([
        blocked_df.get("card_email",    pd.Series()).dropna(),
        blocked_df.get("customer_email", pd.Series()).dropna(),
    ]).str.strip().str.lower().unique().tolist()
    ctx["blocked_email_list"] = [e for e in emails if e]

    # email → blocked customer_id (for match attribution)
    email_to_cid: dict = {}
    for _, brow in blocked_df.iterrows():
        cid = _norm_str(brow.get("customer_id", ""))
        for col in ["card_email", "customer_email"]:
            e = _norm_email(brow.get(col, ""))
            if e:
                email_to_cid.setdefault(e, cid)
    ctx["blocked_email_to_cid"] = email_to_cid

    ctx["blocked_name_list"]     = blocked_df["full_name"].dropna().tolist()
    ctx["blocked_name_cid_list"] = blocked_df["customer_id"].fillna("").tolist()

    _street_rows = blocked_df[blocked_df.get("card_street", pd.Series(dtype=str)).notna()].copy()
    ctx["blocked_street_list"]     = _street_rows["card_street"].str.strip().str.lower().tolist() if "card_street" in _street_rows.columns else []
    ctx["blocked_street_zip_list"] = _street_rows.get("card_zip", pd.Series(dtype=str)).fillna("").str.strip().tolist()

    # Expand |||‑separated multi-value columns into the primary lookup sets/lists.
    # build_blocked_list.py populates these so a fraudster's historical IPs/emails/etc.
    # are all indexed, not just the most recent transaction's values.
    def _expand_multivalue(series: pd.Series) -> list:
        result = []
        for cell in series.dropna():
            for v in str(cell).split("|||"):
                v = v.strip()
                if v:
                    result.append(v)
        return result

    if "all_card_ips" in blocked_df.columns:
        ctx["blocked_ips"].update(_expand_multivalue(blocked_df["all_card_ips"]))
    if "all_card_tokens" in blocked_df.columns:
        ctx["blocked_tokens"].update(_expand_multivalue(blocked_df["all_card_tokens"]))
    if "all_card_emails" in blocked_df.columns:
        extra = [e.lower() for e in _expand_multivalue(blocked_df["all_card_emails"]) if e]
        ctx["blocked_email_list"] = list(dict.fromkeys(ctx["blocked_email_list"] + extra))
    if "all_full_names" in blocked_df.columns:
        extra = [n.lower() for n in _expand_multivalue(blocked_df["all_full_names"]) if n]
        ctx["blocked_name_list"] = list(dict.fromkeys(ctx["blocked_name_list"] + extra))

    return ctx


# ── Section 6: Rule Functions ────────────────────────────────────────────────

def rule_01_auth_codes(row: pd.Series, **_) -> list:
    codes = _parse_auth_codes(row.get("auth_codes", ""))
    results = []
    for code in codes:
        # Per-code override takes precedence over set membership
        if code in AUTH_CODE_RISK_OVERRIDE:
            level = _LEVEL_MAP.get(AUTH_CODE_RISK_OVERRIDE[code], RiskLevel.LOW)
        elif code in AUTH_HIGH:
            level = RiskLevel.HIGH
        elif code in AUTH_MID:
            level = RiskLevel.MEDIUM
        elif code in AUTH_FLAG:
            level = RiskLevel.LOW
        elif code in AUTH_LOW:
            level = RiskLevel.FLAG_LOW
        elif code in AUTH_CODE_INSTANT_BAN:
            level = RiskLevel.LOW
        else:
            continue  # AUTH_IGNORE and unknown codes
        title = AUTH_CODE_TITLES.get(code, code)
        score_override = AUTH_CODE_SCORE_OVERRIDE.get(code)
        rule_name = "AUTH_CODES_INSTANT" if code in AUTH_CODE_INSTANT_BAN else "AUTH_CODES"
        results.append(RuleResult(rule_name, level,
                                  f"Auth code {code} ({title})",
                                  score_override=score_override))
    return results


def rule_02_bin_country(row: pd.Series, **_) -> list:
    if row.get("_r02_flag"):
        country = _norm_str(row.get("bin_country", ""))
        return [RuleResult("BIN_COUNTRY", RiskLevel.HIGH,
                           f"BIN country outside US ({country})")]
    return []


def rule_03_card_email_blocked(row: pd.Series, **_) -> list:
    score = row.get("_r03_score", 0)
    if score is None or pd.isna(score):
        return []
    score = int(score)
    email = _norm_email(row.get("card_email", ""))
    if not email:
        return []
    if score >= EMAIL_BLOCKED_HIGH_THRESHOLD:
        return [RuleResult("EMAIL_BLOCKED", RiskLevel.HIGH,
                           f"Card email matches blocked user ({score}%)")]
    if score >= FUZZY_MATCH_THRESHOLD:
        return [RuleResult("EMAIL_BLOCKED", RiskLevel.MEDIUM,
                           f"Card email likely matches blocked user ({score}%)")]
    return []


def rule_04_email_mismatch(row: pd.Series, **_) -> list:
    if row.get("_r04_flag"):
        return [RuleResult("EMAIL_MISMATCH", RiskLevel.LOW,
                           "Card email does not match customer email")]
    return []


def rule_05_female_name(row: pd.Series, female_names: set, **_) -> list:
    if not female_names:
        return []
    results = []
    first = _norm_str(row.get("card_first_name", "")).lower()
    if first and first in female_names:
        results.append(RuleResult("FEMALE_NAME", RiskLevel.MEDIUM,
                                  f"Female first name on card ({row.get('card_first_name', '')})"))

    card_local = _email_local(row.get("card_email", ""))
    if card_local and card_local in female_names:
        results.append(RuleResult("FEMALE_NAME", RiskLevel.MEDIUM,
                                  f"Female name in card email ({card_local})"))

    cust_local = _email_local(row.get("customer_email", ""))
    if cust_local and cust_local != card_local and cust_local in female_names:
        results.append(RuleResult("FEMALE_NAME", RiskLevel.MEDIUM,
                                  f"Female name in customer email ({cust_local})"))
    return results


def rule_06_name_blocked(row: pd.Series, name_freq: dict, **_) -> list:
    score = row.get("_r06_score", 0)
    if score is None or pd.isna(score):
        return []
    score = int(score)
    if score < FUZZY_MATCH_THRESHOLD:
        return []

    first = _norm_str(row.get("card_first_name", "")).lower()
    freq  = name_freq.get(first, None)

    if freq is not None:
        if freq < NAME_RARITY_RARE_THRESHOLD:
            level = RiskLevel.HIGH
            label = "rare name"
        elif freq > NAME_RARITY_COMMON_THRESHOLD:
            level = RiskLevel.FLAG_LOW
            label = "very common name"
        else:
            level = RiskLevel.MEDIUM
            label = "uncommon name"
    else:
        level = RiskLevel.MEDIUM
        label = "name"

    return [RuleResult("NAME_BLOCKED", level,
                       f"Name matches blocked user ({label}, {score}% match)")]


def rule_07_capitalization(row: pd.Series, **_) -> list:
    if row.get("_r07_flag"):
        first = row.get("card_first_name", "")
        last  = row.get("card_last_name", "")
        bad = []
        if not _is_properly_capitalized(str(first)):
            bad.append(f"first name '{first}'")
        if not _is_properly_capitalized(str(last)):
            bad.append(f"last name '{last}'")
        desc = " and ".join(bad) if bad else "name"
        return [RuleResult("CAPITALIZATION", RiskLevel.FLAG_LOW,
                           f"Name not properly capitalized ({desc})")]
    return []


def rule_08_token_blocked(row: pd.Series, **_) -> list:
    if row.get("_r08_flag"):
        return [RuleResult("TOKEN_BLOCKED", RiskLevel.HIGH,
                           "Card token matches blocked user")]
    return []


def rule_09_ip_blocked(row: pd.Series, ip_usage_map: dict, **_) -> list:
    if not row.get("_r09_flag"):
        return []
    ip = _norm_str(row.get("card_ip", ""))
    legit_count = ip_usage_map.get(ip, 0)
    if legit_count > PUBLIC_IP_LEGITIMATE_USER_THRESHOLD:
        results = [RuleResult("IP_BLOCKED", RiskLevel.LOW,
                              f"IP matches blocked user (shared IP — {legit_count} legit users, downgraded)")]
    else:
        results = [RuleResult("IP_BLOCKED", RiskLevel.HIGH,
                              f"Card IP matches blocked user ({ip})")]
    if row.get("_cust_ip5983_eligible"):
        results.append(RuleResult(
            "IP_FRAUD_CODE_ZERO_ACCEPT", RiskLevel.HIGH,
            "IP match corroborated by auth code 59/83 with 0% acceptance rate",
        ))
    return results


def rule_10_city_mismatch(row: pd.Series, **_) -> list:
    if row.get("_r10_flag"):
        card_city = _norm_str(row.get("card_city", ""))
        ip_city   = _norm_str(row.get("card_ip_city", ""))
        return [RuleResult("CITY_MISMATCH", RiskLevel.LOW,
                           f"Card city ({card_city!r}) does not match IP city ({ip_city!r})")]
    return []


def rule_11_same_city_diff_zip(row: pd.Series, **_) -> list:
    if row.get("_r11_flag"):
        card_zip = _norm_str(row.get("card_zip", ""))
        ip_zip   = _norm_str(row.get("card_ip_zip", ""))
        city     = _norm_str(row.get("card_city", ""))
        return [RuleResult("SAME_CITY_DIFF_ZIP", RiskLevel.LOW,
                           f"Same city ({city!r}) but different ZIPs (card: {card_zip}, IP: {ip_zip})")]
    return []


def rule_12_street_blocked(row: pd.Series, **_) -> list:
    score = row.get("_r12_score", 0)
    if score is None or pd.isna(score):
        return []
    score = int(score)
    if score < FUZZY_MATCH_THRESHOLD:
        return []
    # Skip when both ZIPs are known and differ (same street name in different ZIP = coincidence)
    raw_card_zip = str(row.get("card_zip", "") or "").strip()
    raw_match_zip = str(row.get("_r12_matched_zip", "") or "").strip()
    card_zip  = raw_card_zip[:5].zfill(5) if raw_card_zip else ""
    match_zip = raw_match_zip[:5].zfill(5) if raw_match_zip else ""
    if card_zip and match_zip and card_zip != match_zip:
        return []
    return [RuleResult("STREET_BLOCKED", RiskLevel.HIGH,
                       f"Card street fuzzy matches blocked user street ({score}%)")]


def rule_14_geo_risk(row: pd.Series, **_) -> list:
    results = []
    if row.get("_r14_ip_city_flag"):
        ip_city = _norm_str(row.get("card_ip_city", ""))
        results.append(RuleResult("GEO_RISK_IP", RiskLevel.LOW,
                                  f"IP city in risky list ({ip_city})"))
    if row.get("_r14_city_flag"):
        city = _norm_str(row.get("card_city", ""))
        results.append(RuleResult("GEO_RISK", RiskLevel.LOW,
                                  f"Card city in risky list ({city})"))
    return results


def rule_15_amount_flags(row: pd.Series, **_) -> list:
    results = []
    cents = row.get("total_cents", 0)
    try:
        cents = int(cents)
    except (ValueError, TypeError):
        return []

    # 99-cent ending — always flag regardless of transaction status (probe pattern)
    if cents % 100 == 99:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.LOW,
                                  f"Amount ends in 99 cents — possible test transaction (${cents/100:.2f})"))

    # Non-standard amount only matters on the first transaction
    if row.get("_r15_first_nonstandard"):
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.LOW,
                                  f"First transaction is non-standard amount (${cents/100:.2f})"))

    # Amount thresholds — fire regardless of transaction status
    if cents > AMOUNT_INSTANT_BLOCK_THRESHOLD:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.MEDIUM,
                                  f"Extremely large deposit — exceeds ${AMOUNT_INSTANT_BLOCK_THRESHOLD//100} (${cents/100:.2f})"))
    elif cents > AMOUNT_MAJOR_FLAG_THRESHOLD:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.MEDIUM,
                                  f"Large deposit — exceeds ${AMOUNT_MAJOR_FLAG_THRESHOLD//100} (${cents/100:.2f})"))
    elif cents > AMOUNT_HIGH_RISK_THRESHOLD:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.LOW,
                                  f"Amount exceeds ${AMOUNT_HIGH_RISK_THRESHOLD//100} (${cents/100:.2f})"))
    elif cents > AMOUNT_FLAG_THRESHOLD:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.FLAG_LOW,
                                  f"Amount exceeds ${AMOUNT_FLAG_THRESHOLD//100} (${cents/100:.2f})"))

    # Failed large transaction — explicit flag even though it didn't settle
    status = _norm_str(row.get("transaction_status", ""))
    if status == "FAILED" and cents > AMOUNT_MAJOR_FLAG_THRESHOLD:
        results.append(RuleResult("AMOUNT_FLAG", RiskLevel.LOW,
                                  f"Large failed transaction attempt (${cents/100:.2f})"))

    return results


def rule_16_multiple_card_names(row: pd.Series, **_) -> list:
    if not row.get("_r16_flag"):
        return []
    first = _norm_str(row.get("card_first_name", ""))
    last  = _norm_str(row.get("card_last_name", ""))
    this_name = f"{first} {last}".strip().lower()

    others: list = []
    for name in str(row.get("_r16_all_names", "")).split("|||"):
        name = name.strip()
        if name and name != this_name and name not in others:
            others.append(name)
        if len(others) >= 4:
            break

    if others:
        others_str = ", ".join(n.title() for n in others)
        desc = f"Multiple card names: {first} {last} → {others_str}"
    else:
        desc = f"Multiple card names (this card: {first} {last})"

    results = [RuleResult("MULTIPLE_CARD_NAMES", RiskLevel.HIGH, desc)]
    if row.get("_r16_gender_switch"):
        results.append(RuleResult("GENDER_SWITCH", RiskLevel.MEDIUM,
                                  f"Card names switch gender ({first} {last})"))
    return results


def rule_17_email_name_mismatch(row: pd.Series, **_) -> list:
    email = _norm_email(row.get("card_email", ""))
    if not email or "@" not in email:
        return []
    local = email.split("@")[0]
    # Alpha tokens ≥ 3 chars — typical name components in firstname.lastname style
    tokens = [t for t in re.split(r'[._\-\d]+', local) if len(t) >= 3 and t.isalpha()]
    if len(tokens) < 2:
        return []  # doesn't look like a name-format email
    first = _norm_str(row.get("card_first_name", "")).lower()
    last  = _norm_str(row.get("card_last_name", "")).lower()
    for tok in tokens:
        if first and fuzz.ratio(tok, first) >= 75:
            return []
        if last and fuzz.ratio(tok, last) >= 75:
            return []
    return [RuleResult("EMAIL_NAME_MISMATCH", RiskLevel.LOW,
                       f"{local} → Card name is {first.title()} {last.title()}")]


# ── Rule 13: Failed Transaction Patterns (per-customer grouped apply) ────────

def _analyze_customer_failures(group: pd.DataFrame) -> pd.DataFrame:
    group = group.sort_values("transaction_created_at", na_position="last")
    statuses   = group["transaction_status"].str.upper().tolist()
    auth_raws  = group.get("auth_codes", pd.Series([""] * len(group))).tolist()
    amounts    = group["total_cents"].tolist()
    n          = len(statuses)
    r16_flags  = group["_r16_flag"].tolist() if "_r16_flag" in group.columns else [False] * n

    all_results = []
    n_accepted_cum = 0
    has_5983_cum   = False
    ip5983_eligibles = []

    for i in range(n):
        if statuses[i] != "FAILED":
            n_accepted_cum += 1
        cur_codes = _parse_auth_codes(auth_raws[i])
        if "59" in cur_codes or "83" in cur_codes:
            has_5983_cum = True
        n_hist      = i + 1
        zero_accept = (n_accepted_cum == 0)
        accept_rate = n_accepted_cum / n_hist

        row_results = []

        # Consecutive hard FAILEDs
        if (i >= CONSECUTIVE_FAILURE_INSTANT_BLOCK - 1 and
                all(s == "FAILED" for s in statuses[i - CONSECUTIVE_FAILURE_INSTANT_BLOCK + 1:i + 1])):
            row_results.append(RuleResult(
                "FAILED_PATTERNS", RiskLevel.HIGH,
                f"{CONSECUTIVE_FAILURE_INSTANT_BLOCK}+ consecutive failed transactions (card testing)",
            ))

        # Consecutive soft-failure auth codes (51 / 54 / 72)
        if i >= CONSECUTIVE_SOFT_FAILURE_INSTANT_BLOCK - 1:
            window_codes = []
            for j in range(i - CONSECUTIVE_SOFT_FAILURE_INSTANT_BLOCK + 1, i + 1):
                codes = _parse_auth_codes(auth_raws[j])
                window_codes.append(bool(codes and all(c in AUTH_LOW for c in codes)))
            if all(window_codes):
                row_results.append(RuleResult(
                    "FAILED_PATTERNS", RiskLevel.HIGH,
                    f"{CONSECUTIVE_SOFT_FAILURE_INSTANT_BLOCK}+ consecutive insufficient-funds/expired-card codes",
                ))

        # Escalating amounts across consecutive failures
        if (i >= 1 and statuses[i] == "FAILED" and statuses[i - 1] == "FAILED"):
            try:
                if int(amounts[i]) > int(amounts[i - 1]):
                    row_results.append(RuleResult(
                        "FAILED_PATTERNS", RiskLevel.MEDIUM,
                        "Escalating amounts across consecutive failed attempts",
                    ))
            except (ValueError, TypeError):
                pass

        # Failures concentrated at start of account history (first third)
        first_third = max(1, n // 3)
        if i == n - 1 and n >= 3:
            early_fails = sum(1 for s in statuses[:first_third] if s == "FAILED")
            if early_fails >= CONSECUTIVE_FAILURE_INSTANT_BLOCK:
                row_results.append(RuleResult(
                    "FAILED_PATTERNS", RiskLevel.MEDIUM,
                    "Failures concentrated at start of account history (testing before larger deposit)",
                ))

        # Failures mid-history after previously clean activity (possible account takeover)
        if i >= 2:
            recent_fail = statuses[i] == "FAILED"
            prior_settled = any(s == "SETTLED" for s in statuses[:i])
            no_recent_settled = not any(s == "SETTLED" for s in statuses[max(0, i - 3):i])
            if recent_fail and prior_settled and no_recent_settled:
                row_results.append(RuleResult(
                    "FAILED_PATTERNS", RiskLevel.LOW,
                    "Failures appearing mid-history after previously clean activity (possible account takeover)",
                ))

        if n_hist >= 3 and has_5983_cum and zero_accept:
            row_results.append(RuleResult(
                "FRAUD_CODE_ZERO_ACCEPT", RiskLevel.HIGH,
                f"Auth code 59/83 present with 0% acceptance rate ({n_hist} transactions)",
            ))
        if n_hist >= 2 and bool(r16_flags[i]) and accept_rate < 0.5:
            row_results.append(RuleResult(
                "MULTI_NAME_LOW_ACCEPT", RiskLevel.HIGH,
                f"Multiple card names with {int(accept_rate * 100)}% acceptance rate ({n_hist} transactions)",
            ))
        ip5983_eligibles.append(n_hist >= 3 and has_5983_cum and zero_accept)

        all_results.append(row_results)

    group = group.copy()
    group["_r13_results"]          = all_results
    group["_cust_ip5983_eligible"] = ip5983_eligibles
    return group


def run_rule_13(df: pd.DataFrame) -> pd.DataFrame:
    """Run Rule 13 over all customers grouped. Adds _r13_results column."""
    if "customer_id" not in df.columns or "transaction_status" not in df.columns:
        df["_r13_results"] = [[] for _ in range(len(df))]
        return df
    result = df.groupby("customer_id", group_keys=False).apply(_analyze_customer_failures)
    if "_r13_results" not in result.columns:
        result["_r13_results"] = [[] for _ in range(len(result))]
    if "_cust_ip5983_eligible" not in result.columns:
        result["_cust_ip5983_eligible"] = False
    # pandas drops the groupby key column from the apply result — restore it
    if "customer_id" not in result.columns:
        result["customer_id"] = df["customer_id"]
    return result


# ── Section 7: Aggregation ───────────────────────────────────────────────────

def _precompute_vectorized(df: pd.DataFrame, blocked_df: pd.DataFrame,
                           ctx: dict, female_names: set = frozenset()) -> pd.DataFrame:
    """Add vectorized flag/score columns to df."""
    df = df.copy()

    # Rule 2: BIN country
    df["_r02_flag"] = (
        df["bin_country"].fillna("").str.strip().str.upper() != "US"
    )

    # Rule 4: email mismatch — only fires when customer_email is non-blank
    _card_email = df["card_email"].fillna("").str.strip().str.lower()
    _cust_email = df["customer_email"].fillna("").str.strip().str.lower()
    df["_r04_flag"] = (_card_email != _cust_email) & (_cust_email != "")

    # Rule 7: capitalization
    df["_r07_flag"] = ~(
        df["card_first_name"].apply(lambda x: _is_properly_capitalized(str(x))) &
        df["card_last_name"].apply(lambda x: _is_properly_capitalized(str(x)))
    )

    # Rule 8: card token
    df["_r08_flag"] = df["card_token"].fillna("").str.strip().isin(ctx["blocked_tokens"])

    # Rule 9: IP
    df["_r09_flag"] = df["card_ip"].fillna("").str.strip().isin(ctx["blocked_ips"])

    # Rule 10: city mismatch (exact first, fuzzy passthrough for abbreviations)
    card_city = df["card_city"].fillna("").str.strip().str.lower()
    ip_city   = df["card_ip_city"].fillna("").str.strip().str.lower()
    exact_match = card_city == ip_city
    fuzzy_match = pd.Series([
        (fuzz.ratio(a, b) >= FUZZY_CITY_PASS_THRESHOLD) if (a and b) else True
        for a, b in zip(card_city, ip_city)
    ], index=df.index)
    df["_r10_flag"] = ~exact_match & ~fuzzy_match

    # Rule 11: same city name but different ZIP (address spoofing signal)
    def norm_zip(z):
        return str(z).strip()[:5].zfill(5) if z and not pd.isna(z) else ""
    card_zip_n = df["card_zip"].apply(norm_zip)
    ip_zip_n   = df["card_ip_zip"].apply(norm_zip)
    same_city  = (card_city == ip_city) & (card_city != "")
    diff_zip   = (card_zip_n != ip_zip_n) & (card_zip_n != "") & (ip_zip_n != "")
    df["_r11_flag"] = same_city & diff_zip

    # Rule 14: geo risk — exact + fuzzy match on city names; IP city is primary signal
    _risky_lower = [c.lower() for c in RISKY_CITY_LIST]

    def _is_risky_city(city_raw: str) -> bool:
        c = str(city_raw).strip()
        if not c:
            return False
        c_lower = c.lower()
        if c_lower in _risky_lower:
            return True
        if not _risky_lower:
            return False
        m = fuzz_process.extractOne(c_lower, _risky_lower, scorer=fuzz.ratio)
        return m is not None and m[1] >= RISKY_CITY_FUZZY_THRESHOLD

    df["_r14_ip_city_flag"] = df["card_ip_city"].fillna("").apply(_is_risky_city)
    df["_r14_city_flag"]    = df["card_city"].fillna("").apply(_is_risky_city)

    # Rule 15: amount flags (scalar ops)
    cents = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)
    df["total_cents"] = cents

    # Rule 15: first-nonstandard — detect per customer
    # Use cumcount on sorted df to rank each row within its customer group;
    # rank 0 = chronologically first transaction. Avoids groupby().apply()
    # returning a DataFrame instead of a Series in pandas 2.x.
    if "customer_id" in df.columns:
        rank = (
            df.sort_values("transaction_created_at", na_position="last")
              .groupby("customer_id")
              .cumcount()
        )
        df["_r15_first_nonstandard"] = (rank == 0) & ~df["total_cents"].isin(VALID_AMOUNTS)
    else:
        df["_r15_first_nonstandard"] = ~df["total_cents"].isin(VALID_AMOUNTS)

    # Rule 16: multiple distinct card names per customer
    if "customer_id" in df.columns:
        name_str = (
            df["card_first_name"].fillna("").str.strip() + " " +
            df["card_last_name"].fillna("").str.strip()
        ).str.strip().str.lower()
        df["_full_name_tmp"] = name_str
        df["_r16_flag"] = df.groupby("customer_id")["_full_name_tmp"].transform("nunique") > 1
        # Store all unique names per customer as |||‑separated string for display in reason text
        df["_r16_all_names"] = df.groupby("customer_id")["_full_name_tmp"].transform(
            lambda s: "|||".join(sorted(s.unique()))
        )

        # Gender switch: customer uses both male-coded and female-coded names
        if female_names:
            first_lower = df["card_first_name"].fillna("").str.strip().str.lower()
            df["_name_female_tmp"] = first_lower.isin(female_names)
            any_female = df.groupby("customer_id")["_name_female_tmp"].transform("any")
            all_female = df.groupby("customer_id")["_name_female_tmp"].transform("all")
            df["_r16_gender_switch"] = df["_r16_flag"] & any_female & ~all_female
            df = df.drop(columns=["_name_female_tmp"])
        else:
            df["_r16_gender_switch"] = False

        df = df.drop(columns=["_full_name_tmp"])
    else:
        df["_r16_flag"] = False
        df["_r16_gender_switch"] = False
        df["_r16_all_names"] = ""

    return df


def _precompute_fuzzy(df: pd.DataFrame, ctx: dict) -> pd.DataFrame:
    """Batch fuzzy matching for Rules 3, 6, 12. Adds score + match detail columns."""
    df = df.copy()

    # Rule 3: card_email vs blocked email list
    blocked_emails = ctx["blocked_email_list"]
    blocked_email_to_cid = ctx.get("blocked_email_to_cid", {})
    if blocked_emails:
        queries = df["card_email"].fillna("").str.strip().str.lower().tolist()
        scores, matched_cids_r03, matched_emails_r03 = [], [], []
        for q in queries:
            if not q:
                scores.append(0); matched_cids_r03.append(""); matched_emails_r03.append("")
                continue
            match = fuzz_process.extractOne(q, blocked_emails, scorer=fuzz.ratio)
            scores.append(match[1] if match else 0)
            matched_cids_r03.append(blocked_email_to_cid.get(match[0], "") if match else "")
            matched_emails_r03.append(match[0] if match else "")
        df["_r03_score"]        = scores
        df["_r03_matched_cid"]   = matched_cids_r03
        df["_r03_matched_email"] = matched_emails_r03
    else:
        df["_r03_score"] = 0
        df["_r03_matched_cid"] = ""
        df["_r03_matched_email"] = ""

    # Rule 6: full name vs blocked name list
    blocked_names = ctx["blocked_name_list"]
    blocked_name_cid_list = ctx.get("blocked_name_cid_list", [])
    if blocked_names:
        first = df["card_first_name"].fillna("").str.strip()
        last  = df["card_last_name"].fillna("").str.strip()
        queries = (first + " " + last).str.strip().str.lower().tolist()
        scores, matched_cids_r06, matched_names_r06 = [], [], []
        for q in queries:
            if not q.strip():
                scores.append(0); matched_cids_r06.append(""); matched_names_r06.append("")
                continue
            match = fuzz_process.extractOne(q, blocked_names, scorer=fuzz.token_sort_ratio)
            scores.append(match[1] if match else 0)
            if match:
                idx = match[2]  # rapidfuzz returns (string, score, index)
                matched_cids_r06.append(
                    blocked_name_cid_list[idx] if idx < len(blocked_name_cid_list) else ""
                )
                matched_names_r06.append(match[0])
            else:
                matched_cids_r06.append("")
                matched_names_r06.append("")
        df["_r06_score"]        = scores
        df["_r06_matched_cid"]   = matched_cids_r06
        df["_r06_matched_name"]  = matched_names_r06
    else:
        df["_r06_score"] = 0
        df["_r06_matched_cid"] = ""
        df["_r06_matched_name"] = ""

    # Rule 12: card_street vs blocked street list
    blocked_streets   = ctx["blocked_street_list"]
    blocked_street_zips = ctx.get("blocked_street_zip_list", [])
    if blocked_streets:
        queries = df["card_street"].fillna("").str.strip().str.lower().tolist()
        scores, matched_zips = [], []
        for q in queries:
            if not q:
                scores.append(0); matched_zips.append(""); continue
            match = fuzz_process.extractOne(q, blocked_streets, scorer=fuzz.token_sort_ratio)
            scores.append(match[1] if match else 0)
            if match:
                idx = match[2]
                matched_zips.append(
                    blocked_street_zips[idx] if idx < len(blocked_street_zips) else ""
                )
            else:
                matched_zips.append("")
        df["_r12_score"]       = scores
        df["_r12_matched_zip"] = matched_zips
    else:
        df["_r12_score"]       = 0
        df["_r12_matched_zip"] = ""

    return df


def _apply_row_rules(row: pd.Series, female_names: set, name_freq: dict,
                     ip_usage_map: dict) -> list:
    """Run all per-row rule functions. Returns list[RuleResult]."""
    ctx = dict(female_names=female_names, name_freq=name_freq, ip_usage_map=ip_usage_map)
    results = []
    results += rule_01_auth_codes(row, **ctx)
    results += rule_02_bin_country(row, **ctx)
    results += rule_03_card_email_blocked(row, **ctx)
    results += rule_04_email_mismatch(row, **ctx)
    results += rule_05_female_name(row, **ctx)
    results += rule_06_name_blocked(row, **ctx)
    results += rule_07_capitalization(row, **ctx)
    results += rule_08_token_blocked(row, **ctx)
    results += rule_09_ip_blocked(row, **ctx)
    results += rule_10_city_mismatch(row, **ctx)
    results += rule_11_same_city_diff_zip(row, **ctx)
    results += rule_12_street_blocked(row, **ctx)
    results += list(row.get("_r13_results") or [])
    results += rule_14_geo_risk(row, **ctx)
    results += rule_15_amount_flags(row, **ctx)
    results += rule_16_multiple_card_names(row, **ctx)
    results += rule_17_email_name_mismatch(row, **ctx)
    return results


def score_transaction(rule_results: list) -> Optional[dict]:
    """Aggregate a list of RuleResult into a scored output dict."""
    if not rule_results:
        return None
    def _rule_score(r: RuleResult) -> int:
        if r.score_override is not None:
            return r.score_override
        return RULE_WEIGHTS.get((r.rule_name, r.risk_level.name), r.risk_level.weight)

    sorted_results = sorted(
        rule_results,
        key=lambda r: (r.risk_level.value, _rule_score(r)),
        reverse=True,
    )
    highest = sorted_results[0]
    risk_score = sum(_rule_score(r) for r in rule_results)
    return {
        "risk_level":      highest.risk_level.name,
        "risk_score":      risk_score,
        "flag_count":      len(rule_results),
        "reason_summary":   " | ".join(r.reason for r in sorted_results),
        "rules_triggered":  ", ".join(r.rule_name for r in sorted_results),
        "levels_triggered": ", ".join(r.risk_level.name for r in sorted_results),
    }


def score_all(df: pd.DataFrame, blocked_df: pd.DataFrame,
              female_names: set, name_freq: dict, quiet: bool = False) -> pd.DataFrame:
    """Orchestrate all phases and return a scored DataFrame."""
    ctx = _build_lookup_structures(blocked_df)
    ip_usage_map = build_ip_usage_map(df)

    if not quiet:
        print("  Pre-computing vectorized flags...")
    df = _precompute_vectorized(df, blocked_df, ctx, female_names)

    if not quiet:
        print("  Running batch fuzzy matching (Rules 3, 6, 12)...")
    df = _precompute_fuzzy(df, ctx)

    if not quiet:
        print("  Running per-customer failure pattern analysis (Rule 13)...")
    df = run_rule_13(df)

    if not quiet:
        print("  Scoring each transaction...")
    scored_rows = []
    for _, row in df.iterrows():
        rule_results = _apply_row_rules(row, female_names, name_freq, ip_usage_map)
        scored = score_transaction(rule_results)
        if scored:
            scored_rows.append((row.name, scored))

    if not scored_rows:
        return pd.DataFrame()

    score_index   = [i for i, _ in scored_rows]
    score_records = [s for _, s in scored_rows]
    scores_df = pd.DataFrame(score_records, index=score_index)

    result = df.loc[score_index].join(scores_df)
    return result


# ── Section 8: Output ────────────────────────────────────────────────────────

OUTPUT_DIR = "output"

# All-flags output: one row per suspicious transaction
_ALL_FLAGS_COLS = [
    "payment_id",
    "customer_url",
    "customer_id",
    "risk_level",
    "risk_score",
    "flag_count",
    "reason_summary",
    "matched_blocked_customer_url",
    "match_explanation",
    "rules_triggered",
    "transaction_created_at",
    "transaction_status",
    "transaction_type",
    "total_amount",
    "auth_codes",
    "cvv_response",
    "card_email",
    "customer_email",
    "card_first_name",
    "card_last_name",
    "card_last4",
    "card_token",
    "card_ip",
    "card_type",
    "bank_name",
    "card_product_name",
    "card_segment",
    "card_credit_debit",
    "bin_country",
    "card_city",
    "card_state",
    "card_zip",
    "card_street",
    "card_country",
    "card_ip_city",
    "card_ip_zip",
    "card_region",
    "chargeback_decision",
    "customer_status",
    "liability_owner",
    "error_message",
]

# Should-block output: one row per Functional customer, worst transaction shown
_SHOULD_BLOCK_COLS = [
    "customer_url",
    "customer_id",
    "sample_payment_id",
    "risk_level",
    "risk_score",
    "flag_count",
    "reason_summary",
    "matched_blocked_customer_url",
    "match_explanation",
    "rules_triggered",
    "transaction_created_at",
    "total_amount",
    "card_email",
    "customer_email",
    "card_first_name",
    "card_last_name",
    "card_ip",
    "bin_country",
    "card_city",
    "card_state",
    "card_zip",
    "card_street",
    "card_ip_city",
    "card_ip_zip",
]


def _prepare_out(df: pd.DataFrame, col_list: list) -> pd.DataFrame:
    """Add derived columns, format values, and select/order output columns."""
    out = df.copy()

    if "customer_id" in out.columns and CUSTOMER_URL_TEMPLATE:
        out["customer_url"] = out["customer_id"].apply(
            lambda v: CUSTOMER_URL_TEMPLATE.format(v) if v and not pd.isna(v) else ""
        )
    else:
        out["customer_url"] = ""

    # Matched blocked customer URL (email or name fuzzy match)
    def _get_matched_cid(row):
        if row.get("_r03_score", 0) >= FUZZY_MATCH_THRESHOLD and row.get("_r03_matched_cid"):
            return row["_r03_matched_cid"]
        if row.get("_r06_score", 0) >= FUZZY_MATCH_THRESHOLD and row.get("_r06_matched_cid"):
            return row["_r06_matched_cid"]
        return ""

    if CUSTOMER_URL_TEMPLATE:
        out["matched_blocked_customer_url"] = out.apply(_get_matched_cid, axis=1).apply(
            lambda cid: CUSTOMER_URL_TEMPLATE.format(cid) if cid else ""
        )
    else:
        out["matched_blocked_customer_url"] = ""

    # Human-readable explanation of what was matched
    def _get_match_explanation(row):
        r03_score = int(row.get("_r03_score", 0) or 0)
        r06_score = int(row.get("_r06_score", 0) or 0)
        parts = []
        if r03_score >= FUZZY_MATCH_THRESHOLD:
            card_email = _norm_email(row.get("card_email", ""))
            matched    = row.get("_r03_matched_email", "")
            parts.append(f"Email {r03_score}% match ({card_email} ~ {matched})")
        if r06_score >= FUZZY_MATCH_THRESHOLD:
            card_name = (
                _norm_str(row.get("card_first_name", "")) + " " +
                _norm_str(row.get("card_last_name", ""))
            ).strip()
            matched = row.get("_r06_matched_name", "")
            parts.append(f"Name {r06_score}% match ({card_name} ~ {matched})")
        return " | ".join(parts)

    out["match_explanation"] = out.apply(_get_match_explanation, axis=1)

    if "transaction_created_at" in out.columns:
        out["transaction_created_at"] = pd.to_datetime(
            out["transaction_created_at"], utc=True, errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Convert total_cents → total_amount in dollars
    if "total_cents" in out.columns:
        out["total_amount"] = pd.to_numeric(out["total_cents"], errors="coerce").apply(
            lambda c: f"${c/100:.2f}" if pd.notna(c) else ""
        )

    return out[[c for c in col_list if c in out.columns]]


def _make_should_block(results_df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per Functional (non-blocked) customer, keeping their worst transaction.
    total_cents is replaced with the sum across all their flagged transactions.
    """
    functional = results_df[
        results_df.get("customer_status", pd.Series(dtype=str))
        .fillna("").str.strip()
        .isin(["Functional", ""])
    ].copy()

    if functional.empty:
        return pd.DataFrame()

    functional["_cents"] = pd.to_numeric(functional["total_cents"], errors="coerce").fillna(0)
    customer_totals = functional.groupby("customer_id")["_cents"].sum()

    functional["_sort_score"] = pd.to_numeric(functional["risk_score"], errors="coerce").fillna(0)
    functional = functional.sort_values("_sort_score", ascending=False)

    best = functional.drop_duplicates(subset="customer_id", keep="first").copy()
    best["sample_payment_id"] = best["payment_id"]
    best["total_cents"] = best["customer_id"].map(customer_totals).astype(int)
    best = best.drop(columns=["_sort_score", "_cents"])
    return best


def write_output(results_df: pd.DataFrame, input_path: str,
                 blocked_df: pd.DataFrame) -> None:
    """Write both output CSVs and print a high-risk summary + city candidates to stdout."""
    if results_df.empty:
        print("No transactions met the risk threshold.")
        return

    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(exist_ok=True)

    stem = Path(input_path).stem
    ts   = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    # ── Output 1: all flagged transactions ───────────────────────────────────
    all_flags = _prepare_out(results_df, _ALL_FLAGS_COLS)
    all_flags_path = out_dir / f"{ts}_{stem}_all_flags.csv"
    all_flags.to_csv(all_flags_path, index=False, quoting=1, encoding="utf-8-sig")
    print(f"\nAll flags:    {all_flags_path}  ({len(all_flags):,} transactions)")

    # ── Output 2: one row per Functional customer who should be blocked ──────
    should_block_df = _make_should_block(results_df)
    should_block = _prepare_out(should_block_df, _SHOULD_BLOCK_COLS)
    should_block_path = out_dir / f"{ts}_{stem}_should_block.csv"
    should_block.to_csv(should_block_path, index=False, quoting=1, encoding="utf-8-sig")
    print(f"Should block: {should_block_path}  ({len(should_block):,} customers)")

    # ── Stdout summary: HIGH / MEDIUM from should-block list ─────────────────
    high = should_block[should_block["risk_level"].isin(["HIGH", "MEDIUM"])]
    if not high.empty:
        print(f"\n{'='*80}")
        print(f"SHOULD-BLOCK — HIGH / MEDIUM ({len(high):,} customers)")
        print("="*80)
        display_cols = [c for c in [
            "customer_url", "customer_id", "risk_level", "risk_score",
            "flag_count", "reason_summary",
        ] if c in high.columns]
        print(tabulate(high[display_cols].values.tolist(),
                       headers=display_cols, tablefmt="simple", maxcolwidths=55))

    # ── Stdout: risky IP city candidates among blocked users ─────────────────
    if not blocked_df.empty and "card_ip_city" in blocked_df.columns:
        risky_lower = {c.lower() for c in RISKY_CITY_LIST}
        city_counts = (
            blocked_df["card_ip_city"].fillna("").str.strip()
            .where(lambda x: x != "")
            .dropna()
            .value_counts()
        )
        candidates = [
            (city, count) for city, count in city_counts.items()
            if city.lower() not in risky_lower and count >= 2
        ]
        if candidates:
            print(f"\n{'='*80}")
            print("RISKY CITY CANDIDATES (blocked users by IP city — consider adding to RISKY_CITY_LIST):")
            print("="*80)
            for city, count in candidates[:20]:
                print(f"  {count:4d}  {city}")


# ── Section 9: Entry Point ───────────────────────────────────────────────────

PAYMENTS_DIR = "payments"


def _find_input_file() -> str:
    """Return the first file found in the payments/ directory."""
    payments_dir = Path(PAYMENTS_DIR)
    if not payments_dir.is_dir():
        sys.exit(f"Error: '{PAYMENTS_DIR}/' directory not found.")
    files = sorted(f for f in payments_dir.iterdir() if f.is_file())
    if not files:
        sys.exit(f"Error: No files found in '{PAYMENTS_DIR}/'.")
    return str(files[0])


def _load_file(path: str) -> pd.DataFrame:
    """Load a CSV or Excel file as a string-typed DataFrame."""
    ext = Path(path).suffix.lower()
    if ext in (".xlsx", ".xls"):
        return pd.read_excel(path, dtype=str)
    return pd.read_csv(path, dtype=str)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score payment transactions for fraud risk."
    )
    parser.add_argument(
        "input_file", nargs="?", default=None,
        help=f"Path to input file (CSV or Excel). Defaults to first file in {PAYMENTS_DIR}/",
    )
    parser.add_argument(
        "--threshold", type=int, default=MIN_RISK_THRESHOLD,
        help=f"Minimum risk score to include in output (default: {MIN_RISK_THRESHOLD})",
    )
    args = parser.parse_args()

    input_path = args.input_file or _find_input_file()
    print(f"Loading transactions from {input_path!r}...")
    df = _load_file(input_path)
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    df = df.rename(columns={k: v for k, v in COLUMN_RENAME_MAP.items() if k in df.columns})

    if "transaction_created_at" in df.columns:
        df["transaction_created_at"] = df["transaction_created_at"].apply(parse_timestamp)

    if "total_cents" in df.columns:
        df["total_cents"] = pd.to_numeric(df["total_cents"], errors="coerce").fillna(0).astype(int)

    print("\nPhase 1 — Building blocked user reference list...")
    blocked_df = build_blocked_user_list(df)

    print("\nPhase 2 — Scoring transactions...")
    female_names = load_female_names()
    name_freq    = load_name_frequency()
    print(f"  Female names loaded: {len(female_names):,}")

    results_df = score_all(df, blocked_df, female_names, name_freq)

    if results_df.empty:
        print("No transactions were flagged.")
        return

    if "risk_score" in results_df.columns:
        results_df = results_df[results_df["risk_score"] >= args.threshold]
    print(f"  Transactions at or above threshold ({args.threshold}): {len(results_df):,}")

    write_output(results_df, input_path, blocked_df)


if __name__ == "__main__":
    main()
