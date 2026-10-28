# Architecture

## Components

```
                 ┌───────────────────────────────────────── API Fortress gateway ─────────────────────────────────────────┐
                 │                                                                                                         │
 API client ───▶ │  1 payload size  →  2 input inspection  →  3 JWT  →  4 rate limit  →  5 object ownership  →  decision │ ──▶ protected API
                 │     REQ-002            REQ-001              AUTH-*      RATE-001          AUTHZ-001                     │     (demo_api, :9000)
                 │                                                                                │                        │
                 │                                                                                ▼                        │
                 │                                                           security_events (origin = gateway)            │
 Wazuh ──┐       │                                                                                ▲                        │
 Suricata┼─────▶ │  log_parser (detect + normalise)  →  detection (DET-001…008)  →  security_events (origin = imported)     │
 ModSec ─┘       │                                                                                                         │
                 │  /admin/api  ◀── dashboard (/dashboard)        attack lab (simulator) ──▶ sends real requests to itself  │
                 └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Request pipeline (`app/gateway.py`)

| Step | Rule | Mandatory | Response |
|---|---|---|---|
| Body larger than `MAX_BODY_BYTES` | REQ-002 | yes | 413 |
| SQLi / XSS / traversal / command-injection signature in path, query or body | REQ-001 | no | 400 |
| Authorization header missing | AUTH-001 | yes | 401 |
| Malformed token, bad signature, untrusted `alg` (incl. `none`) | AUTH-002 | yes | 401 |
| Expired token | AUTH-003 | yes | 401 |
| Wrong issuer / audience / missing claims | AUTH-004 | yes | 401 |
| Sliding-window limit exceeded (per user, or per IP if anonymous) | RATE-001 | no | 429 + `Retry-After` |
| Token subject is not the object owner | AUTHZ-001 | no | 403 |
| Owner lookup failed (fail closed) | AUTHZ-002 | yes | 503 |

Decision per mode:

| | Mandatory violation | Policy violation | No violation |
|---|---|---|---|
| Enforce | blocked | **blocked** | allowed |
| Monitor | blocked | flagged, forwarded | allowed |
| Learning | blocked | observed, forwarded, profiled | allowed, profiled |

If the backend is unreachable the gateway returns 502/504 and records `decision=error`.

### Header hygiene

Hop-by-hop headers are removed. Client-supplied `X-Gateway-Secret`,
`X-Authenticated-User`, `X-Authenticated-Role` and `X-Request-ID` are stripped
and replaced by the gateway, so a client cannot impersonate the gateway or another user.

### Object ownership

For routes listed in `PROTECTED_RESOURCES`, the gateway calls the backend's
private `GET /internal/records/{id}/owner` (authenticated with the shared
secret) and compares the owner with the token's `sub`. Positive lookups are
cached for 30 seconds. Missing objects are not cached and are passed through so
the backend returns its own 404.

## Log analysis (`app/log_parser.py`, `app/detection.py`)

1. **Read** NDJSON, JSON arrays or OpenSearch exports. Invalid lines are counted and reported with line numbers.
2. **Detect** the source per record (`transaction` → ModSecurity, `event_type` → Suricata, `rule.level` → Wazuh).
3. **Normalise** to a common schema: timestamp (UTC), severity 0–4, rule id/name, category, groups, src/dest IP and port, protocol, HTTP method/URL/status, user, message. The original record is kept in `raw`.
4. **Classify** with documented rules:

| Rule | Classification | Matches when |
|---|---|---|
| DET-001 | high_severity | source severity ≥ high |
| DET-002 | web_attack | SQLi, XSS, traversal, RCE, LFI/RFI indicators or CRS `attack-*` tags |
| DET-003 | auth_failure | Wazuh authentication groups, failed-login text, HTTP 401 |
| DET-004 | reconnaissance | scanner / scan signatures (nmap, nikto, sqlmap, gobuster…) |
| DET-005 | api_probing | API path answered with 401, 403 or 429 |
| DET-006 | repeated_source | one source IP produces ≥ 5 events in the import |
| DET-007 | upstream_block | the WAF/IPS itself blocked (context only, not an alert on its own) |
| DET-008 | host_integrity | FIM, rootcheck, trojan, reverse-shell indicators |

An event becomes an **alert** when a meaningful rule matched; otherwise it is an
**observation**. Every match stores its reason.

## Data model (`app/models.py`)

- `security_events` — one table for both origins; `origin` (`gateway`/`imported`) and `source` (`api_gateway`, `wazuh`, `suricata`, `modsecurity`) are always set.
- `ingest_batches` — one row per import with parsed/skipped/failed/alert counts and the first 50 errors.
- `gateway_settings` — persisted mode and rate limits.
- `endpoint_profiles` — Learning-mode observations (method, path template, hits, users, status codes, max body).

SQLite by default (WAL mode); Postgres via `DATABASE_URL`.

## Admin console security

- Session: HS256 JWT in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` in production), 8-hour lifetime.
- Login throttled to 10 attempts per 5 minutes per IP; constant-time credential comparison.
- Strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`, `no-store` on admin API responses.
- Push ingestion uses a separate `INGEST_TOKEN`, disabled when empty.
- API docs (`/gateway/docs`) are disabled when `APP_ENV=production`.
