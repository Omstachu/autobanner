# Fraud Detection — Transaction Data Schema

*This document defines the fields extracted from the payment provider export used for fraud detection.*

**Total fields tracked:** 33  |  **Source:** Provider transaction export (CSV)  |  **Amounts stored in cents** (`total_cents` / column EC)

---

## Full Field Reference

| Col | Field Nickname | Category | Description |
|---|---|---|---|
| `B` | `auth_codes` | Authorization | Authorization codes returned by the payment processor |
| `C` | `card_type` | Card Info | Card network type (e.g. Visa, Mastercard, Amex) |
| `J` | `bank_name` | Card Info | Name of the issuing bank |
| `K` | `card_product_name` | Card Info | Card product name (e.g. Mastercard World Elite, Platinum) — not the cardholder name |
| `L` | `card_segment` | Card Info | Card segment classification (Consumer / Commercial / Business) |
| `M` | `card_credit_debit` | Card Info | Whether the card is credit or debit |
| `N` | `bin_country` | Card Location | Country associated with the card BIN (Bank Identification Number) |
| `O` | `card_city` | Card Location | City associated with the card billing address |
| `P` | `card_country` | Card Location | Country associated with the card |
| `Q` | `cvv_response` | Authorization | CVV verification response code from the processor |
| `S` | `card_email` | Customer Identity | Email address associated with the card/transaction |
| `V` | `card_first_name` | Customer Identity | Cardholder first name provided during the transaction |
| `W` | `card_ip` | Customer Identity | IP address of the customer at time of transaction |
| `X` | `card_ip_city` | Customer Location | City derived from the customer IP address geolocation |
| `AF` | `card_region` | Card Location | Region associated with the card |
| `AG` | `card_ip_zip` | Customer Location | ZIP code derived from the customer IP address geolocation |
| `AH` | `card_last_name` | Customer Identity | Cardholder last name provided during the transaction |
| `AL` | `card_state` | Card Location | State associated with the card as a 2-letter code |
| `AM` | `card_street` | Card Location | Street address associated with the card (billing) |
| `AO` | `card_zip` | Card Location | ZIP code associated with the card billing address |
| `BH` | `card_last4` | Card Info | Last 4 digits of the card number |
| `BO` | `transaction_status` | Transaction | Status of the transaction (SETTLED / FAILED / VOIDED) |
| `BP` | `transaction_type` | Transaction | How card info was stored/used (NEW / SAVED / MOBILE) |
| `BQ` | `card_token` | Card Info | Tokenized card identifier stored by the provider |
| `BR` | `chargeback_decision` | Risk | Chargeback protection decision (Not Enabled / Rejected / Approved) |
| `BS` | `transaction_created_at` | Transaction | Timestamp when the transaction was created — format: Wed Apr 22 2026 00:20:44 GMT+0000 (Coordinated Universal Time) |
| `BX` | `customer_status` | Risk | Customer availability status (Blocked / Functional) |
| `CJ` | `customer_id` | Customer Identity | Unique identifier for the customer in the provider system |
| `CK` | `customer_email` | Customer Identity | Customer email address on file with your platform |
| `CP` | `error_message` | Transaction | Error message returned if the transaction failed — same signal as auth_codes (B) |
| `CQ` | `liability_owner` | Risk | Who holds liability for the transaction (blank or Coinflow) |
| `CZ` | `payment_id` | Transaction | Unique identifier for this payment/transaction |
| `EC` | `total_cents` | Transaction | Transaction total amount in cents |

---

## Fields by Category

### Authorization

| Col | Field Nickname | Description |
|---|---|---|
| `B` | `auth_codes` | Authorization codes returned by the payment processor |
| `Q` | `cvv_response` | CVV verification response code from the processor |

### Card Info

| Col | Field Nickname | Description |
|---|---|---|
| `C` | `card_type` | Card network type (e.g. Visa, Mastercard, Amex) |
| `J` | `bank_name` | Name of the issuing bank |
| `K` | `card_product_name` | Card product name (e.g. Mastercard World Elite, Platinum) — not the cardholder name |
| `L` | `card_segment` | Card segment classification (Consumer / Commercial / Business) |
| `M` | `card_credit_debit` | Whether the card is credit or debit |
| `BH` | `card_last4` | Last 4 digits of the card number |
| `BQ` | `card_token` | Tokenized card identifier stored by the provider |

### Card Location

| Col | Field Nickname | Description |
|---|---|---|
| `N` | `bin_country` | Country associated with the card BIN (Bank Identification Number) |
| `O` | `card_city` | City associated with the card billing address |
| `P` | `card_country` | Country associated with the card |
| `AF` | `card_region` | Region associated with the card |
| `AL` | `card_state` | State associated with the card as a 2-letter code |
| `AM` | `card_street` | Street address associated with the card (billing) |
| `AO` | `card_zip` | ZIP code associated with the card billing address |

### Customer Identity

| Col | Field Nickname | Description |
|---|---|---|
| `S` | `card_email` | Email address associated with the card/transaction |
| `V` | `card_first_name` | Cardholder first name provided during the transaction |
| `W` | `card_ip` | IP address of the customer at time of transaction |
| `AH` | `card_last_name` | Cardholder last name provided during the transaction |
| `CJ` | `customer_id` | Unique identifier for the customer in the provider system |
| `CK` | `customer_email` | Customer email address on file with your platform |

### Customer Location

| Col | Field Nickname | Description |
|---|---|---|
| `X` | `card_ip_city` | City derived from the customer IP address geolocation |
| `AG` | `card_ip_zip` | ZIP code derived from the customer IP address geolocation |

### Transaction

| Col | Field Nickname | Description |
|---|---|---|
| `BO` | `transaction_status` | Status of the transaction (SETTLED / FAILED / VOIDED) |
| `BP` | `transaction_type` | How card info was stored/used (NEW / SAVED / MOBILE) |
| `BS` | `transaction_created_at` | Timestamp when the transaction was created — format: Wed Apr 22 2026 00:20:44 GMT+0000 (Coordinated Universal Time) |
| `CP` | `error_message` | Error message returned if the transaction failed — same signal as auth_codes (B) |
| `CZ` | `payment_id` | Unique identifier for this payment/transaction |
| `EC` | `total_cents` | Transaction total amount in cents |

### Risk

| Col | Field Nickname | Description |
|---|---|---|
| `BR` | `chargeback_decision` | Chargeback protection decision (Not Enabled / Rejected / Approved) |
| `BX` | `customer_status` | Customer availability status (Blocked / Functional) |
| `CQ` | `liability_owner` | Who holds liability for the transaction (blank or Coinflow) |

---

## Notes

- **Field nicknames** are snake_case and used as the canonical reference in all Python scripts and engineering documentation.
- **`card_product_name` (K)** is the card product name (e.g. Mastercard World Elite) — not the cardholder name. Cardholder name is composed of `card_first_name` (V) + `card_last_name` (AH).
- **`error_message` (CP)** and **`auth_codes` (B)** represent the same signal. `auth_codes` is the canonical reference.
- **`transaction_created_at` (BS)** timestamp format: `Wed Apr 22 2026 00:20:44 GMT+0000 (Coordinated Universal Time)` — parse accordingly in Python.
- This schema will be updated as additional fields are identified during the rule-building phase.