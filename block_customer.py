"""Block or unblock a Coinflow customer by ID."""

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

COINFLOW_API_URL = os.getenv("COINFLOW_API_URL", "https://api.coinflow.cash/api")
COINFLOW_API_KEY = os.getenv("COINFLOW_API_KEY", "")

if not COINFLOW_API_KEY:
    sys.exit("Error: COINFLOW_API_KEY is not set in .env")

if len(sys.argv) != 2:
    sys.exit(f"Usage: python {sys.argv[0]} <customerId>")

customer_id = sys.argv[1]
url = f"{COINFLOW_API_URL}/merchant/blocked/{customer_id}"

resp = requests.put(
    url,
    json={"reason": "Blocked1", "status": "Blocked"},
    headers={"Authorization": COINFLOW_API_KEY, "Content-Type": "application/json"},
    timeout=15,
)

print(f"Status: {resp.status_code}")
if resp.content:
    print(resp.text)
else:
    print("OK (no response body)")
