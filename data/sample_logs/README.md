# Sample logs

These files use the exact record formats produced by each tool, so the full
ingestion and detection pipeline can be exercised before your own lab logs are
available. They describe a fictional lab (`api.lab.local`, 10.0.2.15) and use
documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for attackers.

| File | Format | Records | Notes |
|---|---|---|---|
| `wazuh_alerts.json` | Wazuh `alerts.json` (NDJSON) | 20 | SSH brute force, web attacks, FIM, rootcheck, reverse shell |
| `suricata_eve.json` | Suricata EVE JSON | 18 lines | Scans, SQLi/XSS/traversal alerts, HTTP, DNS, anomaly; includes `stats`/`flow` (skipped) and one deliberately truncated line (reported as a parse failure) |
| `modsecurity_audit.json` | ModSecurity v3 JSON audit log | 6 | OWASP CRS 942100, 941100, 930100, 932100, 913100 and one clean transaction |

For your report and demonstration, replace these with logs exported from your own
Wazuh / Suricata / ModSecurity setup (see `docs/INTEGRATION.md`) and state the
source, collection period and any sanitisation applied.
