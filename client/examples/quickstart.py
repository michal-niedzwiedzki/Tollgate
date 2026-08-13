"""Pay for one API call. Needs a local stack and a `quickstart` provider — see README.md."""

import secrets

import httpx

from tollgate import Session

GATEWAY = "http://localhost:8080"

session = Session(signer="0x" + secrets.token_bytes(32).hex(), gateway=GATEWAY)
httpx.post(
    f"{GATEWAY}/v1/budgets",
    json={"payer": session.address, "max_total": "1.00", "max_per_request": "0.05"},
)

response = session.get(f"{GATEWAY}/v1/proxy/quickstart/ok")
print("status :", response.status_code)
print("body   :", response.json())
print("receipt:", session.receipts()[0]["signature"])
