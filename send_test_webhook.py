"""
Send a test webhook to the local webhook server with a valid Coinflow-Signature header.

Usage:
    python send_test_webhook.py <paymentId>
    python send_test_webhook.py <paymentId> --customer-id <uuid> --event-type "Card Payment Declined"
    python send_test_webhook.py <paymentId> --port 8080
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time

import requests
from dotenv import load_dotenv

load_dotenv()

COINFLOW_VALIDATION_KEY = os.getenv("COINFLOW_VALIDATION_KEY", "")

EVENT_TYPES = ["Settled", "Card Payment Authorized", "Card Payment Declined"]


def _sign(body: str, validation_key: str) -> str:
    timestamp = str(int(time.time()))
    signed_payload = f"{timestamp}.{body}"
    digest = hmac.new(
        validation_key.encode(), signed_payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send a signed test webhook to the local webhook server"
    )
    parser.add_argument("payment_id", help="Coinflow payment ID to include in the webhook")
    parser.add_argument("--customer-id", default="", help="Customer UUID (optional)")
    parser.add_argument(
        "--event-type", default="Settled", choices=EVENT_TYPES,
        help="Webhook event type (default: Settled)",
    )
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    args = parser.parse_args()

    payload = {
        "eventType": args.event_type,
        "category": "Purchase",
        "created": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "data": {
            "id": args.payment_id,
            "customerId": args.customer_id,
            "rawCustomerId": args.customer_id,
            "total": {"cents": 0, "currency": "USD"},
        },
    }

    body = json.dumps(payload, separators=(",", ":"))

    if COINFLOW_VALIDATION_KEY:
        signature = _sign(body, COINFLOW_VALIDATION_KEY)
        print(f"  Signing with COINFLOW_VALIDATION_KEY")
    else:
        signature = None
        print("  Warning: COINFLOW_VALIDATION_KEY not set — sending without signature (verification must be disabled on server)")

    url = f"http://localhost:{args.port}/webhook"
    print(f"  POST {url}")
    print(f"  eventType: {args.event_type}  paymentId: {args.payment_id}")

    headers = {"Content-Type": "application/json"}
    if signature:
        headers["Coinflow-Signature"] = signature

    try:
        resp = requests.post(url, data=body, headers=headers, timeout=30)
    except requests.exceptions.ConnectionError:
        sys.exit(f"Could not connect to {url} — is the server running?")

    print(f"  Response: {resp.status_code}  {resp.text}")


if __name__ == "__main__":
    main()
