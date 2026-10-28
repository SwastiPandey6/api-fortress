"""Command-line attack simulation against a running gateway.

Sends legitimate and malicious requests and prints a pass/fail report. The
expected status codes assume the gateway is in Enforce mode.

    python scripts/simulate_attacks.py
    python scripts/simulate_attacks.py --url https://your-gateway.example.com
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time

import httpx

USERS = {"alice": "Alice@123", "bob": "Bob@123", "mallory": "Mallory@123"}


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--flood", type=int, default=40, help="requests to send in the rate-limit test")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.url, timeout=10, headers={"User-Agent": "api-fortress-cli-simulator"})
    results: list[tuple[str, int, list[int]]] = []

    def check(label: str, resp: httpx.Response, expected: list[int]) -> httpx.Response:
        results.append((label, resp.status_code, expected))
        ok = resp.status_code in expected
        rule = ""
        try:
            rule = resp.json().get("rule") or ""
        except ValueError:
            pass
        print(f"  {'PASS' if ok else 'FAIL'}  {resp.status_code:>3}  {label:<52} {rule}")
        return resp

    def login(user: str) -> str:
        r = check(f"login as {user}", c.post("/auth/login", json={"username": user, "password": USERS[user]}), [200])
        return r.json()["access_token"]

    print(f"\nAPI Fortress attack simulation -> {args.url}\n")
    alice = login("alice")
    h = {"Authorization": f"Bearer {alice}"}
    check("alice reads her own record 101", c.get("/records/101", headers=h), [200])
    check("alice reads bob's record 202 (BOLA)", c.get("/records/202", headers=h), [403])
    check("alice overwrites bob's record 202 (BOLA)", c.put("/records/202", headers=h, json={"title": "x", "content": "y"}), [403])
    check("no token", c.get("/records/101"), [401])
    exp = int(time.time()) + 600
    none_tok = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'alice', 'role': 'admin', 'exp': exp, 'iat': exp - 600})}."
    check("unsigned alg=none token", c.get("/records/202", headers={"Authorization": f"Bearer {none_tok}"}), [401])
    hdr, _, sig = alice.split(".")
    tampered = f"{hdr}.{b64({'sub': 'bob', 'exp': exp, 'iat': exp - 600})}.{sig}"
    check("tampered token payload", c.get("/records/202", headers={"Authorization": f"Bearer {tampered}"}), [401])
    check("SQL injection in query string", c.get("/records/101", params={"q": "' OR 1=1--"}, headers=h), [400])
    check("XSS in JSON body", c.post("/records", headers=h, json={"title": "<script>alert(1)</script>", "content": "x"}), [400])
    check("path traversal", c.get("/records", params={"file": "../../etc/passwd"}, headers=h), [400])

    mallory = login("mallory")
    codes = [c.get("/records/301", headers={"Authorization": f"Bearer {mallory}"}).status_code for _ in range(args.flood)]
    limited = codes.count(429)
    label = f"flood {args.flood} requests ({limited} rate-limited)"
    results.append((label, 429 if limited else 200, [429]))
    print(f"  {'PASS' if limited else 'FAIL'}  {429 if limited else 200:>3}  {label}")

    passed = sum(1 for _, s, e in results if s in e)
    print(f"\n{passed}/{len(results)} checks behaved as expected.\n")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
