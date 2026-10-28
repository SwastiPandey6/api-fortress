"""Security log ingestion.

Supported formats (auto-detected per record):

* Wazuh alerts        - `/var/ossec/logs/alerts/alerts.json` (NDJSON) or an
                        OpenSearch/Wazuh-dashboard JSON export (`hits.hits[]._source`)
* Suricata EVE JSON   - `/var/log/suricata/eve.json` (NDJSON)
* ModSecurity v3 JSON - audit log with `SecAuditLogFormat JSON`

Each record is normalised into a common event structure while the original
record is preserved in `raw`. Malformed lines are counted and reported, never
silently dropped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

SOURCES = ("wazuh", "suricata", "modsecurity")
SURICATA_NOISE = {"stats", "flow", "netflow"}  # high-volume, non-security records


@dataclass
class ParseResult:
    source_hint: str
    events: list[dict] = field(default_factory=list)
    total: int = 0
    skipped: int = 0
    errors: list[dict] = field(default_factory=list)  # first N errors, for display
    failed_count: int = 0

    @property
    def failed(self) -> int:
        return self.failed_count


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _get(d: Any, *path, default=None):
    for key in path:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the timestamp variants used by Wazuh, Suricata and ModSecurity into naive UTC."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
    text = str(value).strip()
    candidates = [text]
    # Suricata/Wazuh: 2026-10-28T12:00:00.123456+0000  -> make +00:00
    if len(text) > 5 and text[-5] in "+-" and text[-4:].isdigit():
        candidates.append(text[:-2] + ":" + text[-2:])
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    for c in candidates:
        try:
            dt = datetime.fromisoformat(c)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            pass
    for fmt in ("%a %b %d %H:%M:%S %Y", "%d/%b/%Y:%H:%M:%S %z", "%Y %b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            pass
    return None


def wazuh_severity(level: Any) -> int:
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return 0
    if lvl >= 13:
        return 4
    if lvl >= 10:
        return 3
    if lvl >= 7:
        return 2
    if lvl >= 4:
        return 1
    return 0


def suricata_severity(sev: Any) -> int:
    try:
        s = int(sev)
    except (TypeError, ValueError):
        return 0
    return {1: 3, 2: 2, 3: 1}.get(s, 0)


_MODSEC_NAMED = {"EMERGENCY": 4, "ALERT": 4, "CRITICAL": 4, "ERROR": 3, "WARNING": 2, "NOTICE": 1, "INFO": 0, "DEBUG": 0}


def modsec_severity(sev: Any) -> int:
    if sev is None:
        return 0
    text = str(sev).strip().upper()
    if text in _MODSEC_NAMED:
        return _MODSEC_NAMED[text]
    try:
        n = int(text)
    except ValueError:
        return 0
    return {0: 4, 1: 4, 2: 4, 3: 3, 4: 2, 5: 1}.get(n, 0)


def _int_or_none(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _base(source: str) -> dict:
    return {
        "source": source,
        "timestamp": None,
        "event_type": "alert",
        "severity": 0,
        "rule_id": None,
        "rule_name": None,
        "category": None,
        "groups": [],
        "src_ip": None,
        "src_port": None,
        "dest_ip": None,
        "dest_port": None,
        "protocol": None,
        "http_method": None,
        "url": None,
        "http_status": None,
        "user": None,
        "message": None,
    }


# --------------------------------------------------------------------------
# per-source normalisers
# --------------------------------------------------------------------------
def detect_source(rec: dict) -> str | None:
    if not isinstance(rec, dict):
        return None
    if "transaction" in rec and isinstance(rec["transaction"], dict):
        return "modsecurity"
    if "event_type" in rec and ("src_ip" in rec or "flow_id" in rec or "in_iface" in rec or "timestamp" in rec):
        return "suricata"
    if isinstance(rec.get("rule"), dict) and ("level" in rec["rule"] or "description" in rec["rule"]):
        return "wazuh"
    return None


def normalize_wazuh(rec: dict) -> dict:
    ev = _base("wazuh")
    rule = rec.get("rule") or {}
    data = rec.get("data") or {}
    ev["timestamp"] = parse_timestamp(rec.get("timestamp") or rec.get("@timestamp"))
    ev["severity"] = wazuh_severity(rule.get("level"))
    ev["rule_id"] = str(rule.get("id")) if rule.get("id") is not None else None
    ev["rule_name"] = rule.get("description")
    ev["groups"] = list(rule.get("groups") or [])
    ev["category"] = ", ".join(ev["groups"][:3]) or None
    ev["src_ip"] = data.get("srcip") or _get(rec, "agent", "ip")
    ev["src_port"] = _int_or_none(data.get("srcport"))
    ev["dest_ip"] = data.get("dstip")
    ev["dest_port"] = _int_or_none(data.get("dstport"))
    ev["protocol"] = data.get("protocol")
    ev["url"] = data.get("url")
    ev["http_status"] = _int_or_none(data.get("id")) if data.get("url") else None
    ev["http_method"] = data.get("protocol") if str(data.get("protocol", "")).upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} else None
    ev["user"] = data.get("srcuser") or data.get("dstuser")
    ev["message"] = rec.get("full_log")
    ev["event_type"] = "alert"
    ev["agent"] = _get(rec, "agent", "name")
    ev["level"] = rule.get("level")
    return ev


def normalize_suricata(rec: dict) -> dict:
    ev = _base("suricata")
    etype = rec.get("event_type", "unknown")
    alert = rec.get("alert") or {}
    http = rec.get("http") or {}
    ev["timestamp"] = parse_timestamp(rec.get("timestamp"))
    ev["event_type"] = etype
    ev["src_ip"] = rec.get("src_ip")
    ev["src_port"] = _int_or_none(rec.get("src_port"))
    ev["dest_ip"] = rec.get("dest_ip")
    ev["dest_port"] = _int_or_none(rec.get("dest_port"))
    ev["protocol"] = rec.get("app_proto") or rec.get("proto")
    ev["http_method"] = http.get("http_method")
    ev["url"] = (http.get("hostname") or "") + (http.get("url") or "") if http.get("url") else None
    ev["http_status"] = _int_or_none(http.get("status"))
    if etype == "alert":
        ev["severity"] = suricata_severity(alert.get("severity"))
        ev["rule_id"] = str(alert.get("signature_id")) if alert.get("signature_id") is not None else None
        ev["rule_name"] = alert.get("signature")
        ev["category"] = alert.get("category")
        ev["action"] = alert.get("action")
    elif etype == "anomaly":
        ev["severity"] = 1
        ev["rule_name"] = _get(rec, "anomaly", "event") or "Protocol anomaly"
        ev["category"] = "anomaly"
    else:
        ev["rule_name"] = f"{etype} event"
        ev["category"] = etype
    ev["message"] = alert.get("signature") or (f"{ev['http_method']} {ev['url']}" if ev["url"] else None)
    return ev


def normalize_modsecurity(rec: dict) -> dict:
    ev = _base("modsecurity")
    tx = rec.get("transaction") or {}
    req = tx.get("request") or {}
    resp = tx.get("response") or {}
    messages = tx.get("messages") or rec.get("messages") or []
    ev["timestamp"] = parse_timestamp(tx.get("time_stamp") or tx.get("time"))
    ev["src_ip"] = tx.get("client_ip")
    ev["src_port"] = _int_or_none(tx.get("client_port"))
    ev["dest_ip"] = tx.get("host_ip")
    ev["dest_port"] = _int_or_none(tx.get("host_port"))
    ev["protocol"] = "http"
    ev["http_method"] = req.get("method")
    ev["url"] = req.get("uri")
    ev["http_status"] = _int_or_none(resp.get("http_code"))
    ev["event_type"] = "waf_transaction"
    best_sev, best = -1, None
    rule_ids = []
    for m in messages:
        det = m.get("details") or {}
        sev = modsec_severity(det.get("severity"))
        if det.get("ruleId"):
            rule_ids.append(str(det["ruleId"]))
        if sev > best_sev:
            best_sev, best = sev, m
    if best:
        det = best.get("details") or {}
        ev["severity"] = max(best_sev, 0)
        ev["rule_id"] = str(det.get("ruleId")) if det.get("ruleId") else None
        ev["rule_name"] = best.get("message")
        ev["groups"] = list(det.get("tags") or [])
        ev["category"] = next((t for t in ev["groups"] if t.startswith("attack-")), None)
        ev["message"] = det.get("data") or det.get("match")
    else:
        ev["rule_name"] = "WAF transaction (no rule matched)"
    ev["matched_rule_ids"] = rule_ids
    ev["intervention"] = bool(ev["http_status"] and ev["http_status"] >= 400 and messages)
    return ev


NORMALIZERS = {"wazuh": normalize_wazuh, "suricata": normalize_suricata, "modsecurity": normalize_modsecurity}


# --------------------------------------------------------------------------
# file-level parsing
# --------------------------------------------------------------------------
def _iter_records(text: str) -> Iterable[tuple[int, Any, str | None]]:
    """Yield (line_no, record, error). Supports NDJSON, JSON arrays and OpenSearch exports."""
    stripped = text.lstrip("﻿").strip()
    if not stripped:
        return
    if stripped[0] in "[{":
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if doc is not None:
            if isinstance(doc, list):
                for i, r in enumerate(doc, 1):
                    yield i, r, None
                return
            hits = _get(doc, "hits", "hits")
            if isinstance(hits, list):
                for i, h in enumerate(hits, 1):
                    yield i, (h.get("_source", h) if isinstance(h, dict) else h), None
                return
            if isinstance(doc, dict):
                yield 1, doc, None
                return
    for i, line in enumerate(stripped.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            yield i, json.loads(line), None
        except json.JSONDecodeError as exc:
            yield i, None, f"Invalid JSON: {exc.msg} (column {exc.colno})"


def parse_content(content: bytes | str, source_hint: str = "auto", max_errors: int = 50) -> ParseResult:
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    hint = source_hint if source_hint in SOURCES else "auto"
    result = ParseResult(source_hint=hint)
    failed = 0

    def fail(line_no: int, message: str) -> None:
        nonlocal failed
        failed += 1
        if len(result.errors) < max_errors:
            result.errors.append({"line": line_no, "error": message})

    for line_no, rec, err in _iter_records(text):
        result.total += 1
        if err:
            fail(line_no, err)
            continue
        source = detect_source(rec)
        if source is None:
            fail(line_no, "Unrecognised record format")
            continue
        if hint != "auto" and source != hint:
            fail(line_no, f"Record looks like {source}, expected {hint}")
            continue
        if source == "suricata" and rec.get("event_type") in SURICATA_NOISE:
            result.skipped += 1
            continue
        try:
            ev = NORMALIZERS[source](rec)
        except Exception as exc:  # defensive: a single bad record never aborts an import
            fail(line_no, f"Normalisation failed: {exc.__class__.__name__}")
            continue
        ev["raw"] = rec
        ev["line"] = line_no
        result.events.append(ev)
    result.failed_count = failed
    return result
