"""Tests for log parsing and normalisation."""
import json
from pathlib import Path

from app.log_parser import detect_source, parse_content, parse_timestamp

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "sample_logs"


def test_wazuh_sample_parses_fully():
    r = parse_content((SAMPLES / "wazuh_alerts.json").read_bytes())
    assert r.total == len(r.events) and r.failed == 0
    ev = r.events[0]
    assert ev["source"] == "wazuh" and ev["rule_id"] == "5710" and ev["severity"] == 1
    assert ev["src_ip"] == "203.0.113.45" and ev["timestamp"] is not None
    assert "authentication_failed" in ev["groups"]


def test_suricata_sample_skips_noise_and_reports_malformed_line():
    r = parse_content((SAMPLES / "suricata_eve.json").read_bytes())
    assert r.skipped == 2  # stats + flow
    assert r.failed == 1 and "Invalid JSON" in r.errors[0]["error"]
    alerts = [e for e in r.events if e["event_type"] == "alert"]
    sqli = next(e for e in alerts if e["rule_id"] == "2006445")
    assert sqli["severity"] == 3 and sqli["http_status"] == 400 and "UNION" in sqli["url"]


def test_modsecurity_sample_picks_highest_severity_message():
    r = parse_content((SAMPLES / "modsecurity_audit.json").read_bytes())
    assert r.failed == 0 and len(r.events) == 6
    first = r.events[0]
    assert first["rule_id"] == "942100" and first["severity"] == 4 and first["category"] == "attack-sqli"
    assert first["http_status"] == 403 and first["intervention"] is True


def test_json_array_and_opensearch_export_formats():
    rec = {"timestamp": "2026-10-27T10:00:00.000+0000", "rule": {"level": 12, "id": "1", "description": "x"}}
    arr = parse_content(json.dumps([rec, rec]))
    assert len(arr.events) == 2 and arr.events[0]["severity"] == 3
    export = parse_content(json.dumps({"hits": {"hits": [{"_source": rec}]}}))
    assert len(export.events) == 1


def test_source_hint_mismatch_is_reported():
    line = json.dumps({"timestamp": "2026-10-27T10:00:00Z", "event_type": "alert", "src_ip": "1.1.1.1", "alert": {}})
    r = parse_content(line, source_hint="wazuh")
    assert r.failed == 1 and "expected wazuh" in r.errors[0]["error"]


def test_garbage_and_empty_input_are_safe():
    assert parse_content("").total == 0
    r = parse_content("not json\n{\"hello\": 1}\n")
    assert r.total == 2 and r.failed == 2 and not r.events


def test_missing_fields_do_not_crash():
    r = parse_content('{"rule": {"description": "bare"}}')
    assert r.events[0]["severity"] == 0 and r.events[0]["timestamp"] is None


def test_detect_source():
    assert detect_source({"transaction": {}}) == "modsecurity"
    assert detect_source({"event_type": "alert", "src_ip": "x"}) == "suricata"
    assert detect_source({"rule": {"level": 3}}) == "wazuh"
    assert detect_source({"foo": 1}) is None


def test_timestamp_variants():
    assert parse_timestamp("2026-10-27T09:00:00.123+0000").hour == 9
    assert parse_timestamp("2026-10-27T14:30:00+05:30").hour == 9
    assert parse_timestamp("Tue Oct 27 09:21:00 2026").minute == 21
    assert parse_timestamp("nonsense") is None
