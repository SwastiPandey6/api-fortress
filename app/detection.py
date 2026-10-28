"""Detection and classification rules for imported security events.

Every match records the rule, the reason it matched and a severity. A match
means a detection rule fired; it is *not* proof that an attack succeeded.

Rule catalogue
--------------
DET-001  High-severity source alert      source severity >= high
DET-002  Web application attack          SQLi / XSS / traversal / RCE indicators
DET-003  Authentication failure          failed logins, invalid users, HTTP 401
DET-004  Reconnaissance / scanning       scanners and network scan signatures
DET-005  API probing                     API paths answered with 401/403/429
DET-006  Repeated source                 one source IP produces >= N events in a batch
DET-007  Blocked by upstream control     WAF/IPS reports a blocking action
DET-008  Host integrity / malware        FIM changes, rootkit or trojan findings
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

REPEAT_THRESHOLD = 5

WEB_ATTACK = re.compile(
    r"(sql\s*injection|sqli|union\s+select|\bor\s+1=1|xss|cross[\s-]site\s+scripting|<script|path\s+traversal"
    r"|directory\s+traversal|\.\./|remote\s+code\s+execution|\brce\b|command\s+injection|shellshock|lfi|rfi"
    r"|local\s+file\s+inclusion|web\s+attack|attack-(sqli|xss|lfi|rfi|rce|injection))",
    re.IGNORECASE,
)
AUTH_FAIL = re.compile(
    r"(authentication\s+fail|failed\s+password|invalid\s+user|login\s+fail|failed\s+login|brute\s*force"
    r"|multiple\s+authentication\s+failures|non-existent\s+user)",
    re.IGNORECASE,
)
AUTH_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login", "brute_force"}
RECON = re.compile(
    r"(\bscan\b|scanner|scanning|nmap|nikto|sqlmap|dirbuster|gobuster|masscan|zgrab|wpscan|recon"
    r"|information\s+leak|network\s+scan|attempted\s+information\s+leak)",
    re.IGNORECASE,
)
HOST_INTEGRITY = re.compile(r"(rootcheck|rootkit|trojan|syscheck|integrity\s+checksum|malware|reverse\s+shell)", re.IGNORECASE)
HOST_GROUPS = {"syscheck", "rootcheck", "syscheck_file", "malware", "virustotal"}
API_PATH = re.compile(r"(/api/|/v\d+/|/graphql|/records|/users|/auth)", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    classification: str
    severity: int
    check: Callable[[dict], str | None]  # returns reason when matched


def _text(ev: dict) -> str:
    parts = [ev.get("rule_name"), ev.get("category"), ev.get("message"), ev.get("url"), " ".join(ev.get("groups") or [])]
    return " ".join(str(p) for p in parts if p)


def _high_sev(ev):
    if ev.get("severity", 0) >= 3:
        return f"{ev['source']} reported severity {('high', 'critical')[ev['severity'] - 3]}"
    return None


def _web_attack(ev):
    m = WEB_ATTACK.search(_text(ev))
    return f"web attack indicator '{m.group(0)}'" if m else None


def _auth_fail(ev):
    if AUTH_GROUPS.intersection(ev.get("groups") or []):
        return "source tagged the event as an authentication failure"
    m = AUTH_FAIL.search(_text(ev))
    if m:
        return f"authentication failure indicator '{m.group(0)}'"
    if ev.get("http_status") == 401:
        return "HTTP 401 response"
    return None


def _recon(ev):
    m = RECON.search(_text(ev))
    return f"reconnaissance indicator '{m.group(0)}'" if m else None


def _api_probe(ev):
    url = ev.get("url") or ""
    if ev.get("http_status") in (401, 403, 429) and API_PATH.search(url):
        return f"API path {url[:80]} answered with HTTP {ev['http_status']}"
    return None


def _host_integrity(ev):
    if HOST_GROUPS.intersection(ev.get("groups") or []):
        return "source tagged the event as a host integrity finding"
    m = HOST_INTEGRITY.search(_text(ev))
    return f"host integrity indicator '{m.group(0)}'" if m else None


def _upstream_block(ev):
    if ev.get("action") == "blocked":
        return "IPS action was 'blocked'"
    if ev.get("source") == "modsecurity" and ev.get("intervention"):
        return f"WAF intervention (HTTP {ev.get('http_status')})"
    return None


RULES: list[Rule] = [
    Rule("DET-002", "Web application attack", "web_attack", 3, _web_attack),
    Rule("DET-003", "Authentication failure", "auth_failure", 2, _auth_fail),
    Rule("DET-004", "Reconnaissance / scanning", "reconnaissance", 2, _recon),
    Rule("DET-005", "API probing", "api_probing", 2, _api_probe),
    Rule("DET-008", "Host integrity / malware", "host_integrity", 2, _host_integrity),
    Rule("DET-007", "Blocked by upstream control", "upstream_block", 1, _upstream_block),
    Rule("DET-001", "High-severity source alert", "high_severity", 3, _high_sev),
]

CLASS_PRIORITY = ["web_attack", "host_integrity", "auth_failure", "reconnaissance", "api_probing", "repeated_source",
                  "high_severity", "upstream_block", "informational"]

RULE_CATALOGUE = [
    {"rule_id": r.rule_id, "name": r.name, "classification": r.classification, "severity": r.severity} for r in RULES
] + [{"rule_id": "DET-006", "name": "Repeated source", "classification": "repeated_source", "severity": 2}]


def classify(events: list[dict], repeat_threshold: int = REPEAT_THRESHOLD) -> list[dict]:
    """Annotate normalised events with matches, classification, decision and severity."""
    ip_counts = Counter(e.get("src_ip") for e in events if e.get("src_ip"))
    for ev in events:
        matches = []
        for rule in RULES:
            reason = rule.check(ev)
            if reason:
                matches.append({"rule_id": rule.rule_id, "name": rule.name, "classification": rule.classification,
                                "severity": rule.severity, "reason": reason})
        ip = ev.get("src_ip")
        if ip and ip_counts[ip] >= repeat_threshold:
            matches.append({"rule_id": "DET-006", "name": "Repeated source", "classification": "repeated_source",
                            "severity": 2, "reason": f"{ip} produced {ip_counts[ip]} events in this import"})

        classes = {m["classification"] for m in matches}
        classification = next((c for c in CLASS_PRIORITY if c in classes), "informational")
        severity = max([ev.get("severity", 0)] + [m["severity"] for m in matches if m["rule_id"] != "DET-007"])
        meaningful = [m for m in matches if m["rule_id"] not in ("DET-007",)]
        decision = "alert" if meaningful and (severity >= 2 or classification not in ("informational", "upstream_block")) else "observed"

        ev["matches"] = matches
        ev["classification"] = classification
        ev["detection_severity"] = min(severity, 4)
        ev["decision"] = decision
    return events


def to_db_record(ev: dict) -> dict:
    """Map a classified, normalised event onto SecurityEvent columns."""
    primary = ev["matches"][0] if ev.get("matches") else None
    reason = "; ".join(m["reason"] for m in ev.get("matches", [])) or None
    source_rule = f"{ev['source']}:{ev['rule_id']}" if ev.get("rule_id") else None
    raw = dict(ev.get("raw") or {})
    return {
        "source": ev["source"],
        "event_type": str(ev.get("event_type") or "alert")[:64],
        "event_time": ev.get("timestamp"),
        "decision": ev["decision"],
        "classification": ev["classification"],
        "rule_id": (source_rule or (primary["rule_id"] if primary else None)),
        "rule_name": (ev.get("rule_name") or (primary["name"] if primary else None)),
        "reason": reason,
        "matches": json.dumps(ev.get("matches", [])),
        "severity": ev["detection_severity"],
        "method": ev.get("http_method"),
        "path": (ev.get("url") or None) and str(ev["url"])[:2000],
        "status_code": ev.get("http_status"),
        "client_ip": ev.get("src_ip"),
        "dest_ip": ev.get("dest_ip"),
        "username": ev.get("user"),
        "raw": json.dumps(raw, default=str)[:200_000],
    }
