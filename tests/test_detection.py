"""Tests for the detection rules applied to imported events."""
from app.detection import classify


def ev(**kw):
    base = {"source": "suricata", "severity": 0, "rule_name": None, "category": None, "message": None,
            "url": None, "groups": [], "http_status": None, "src_ip": None}
    base.update(kw)
    return base


def rule_ids(e):
    return {m["rule_id"] for m in e["matches"]}


def test_web_attack_detected_with_reason():
    [e] = classify([ev(rule_name="ET WEB_SERVER Possible SQL Injection Attempt", severity=3)])
    assert e["classification"] == "web_attack" and e["decision"] == "alert"
    assert {"DET-002", "DET-001"} <= rule_ids(e)
    assert any("sql injection" in m["reason"].lower() for m in e["matches"])


def test_auth_failure_from_groups():
    [e] = classify([ev(source="wazuh", groups=["sshd", "authentication_failed"], severity=1)])
    assert e["classification"] == "auth_failure"


def test_api_probing():
    [e] = classify([ev(url="/api/records/202", http_status=403)])
    assert e["classification"] == "api_probing"


def test_repeated_source_threshold():
    events = classify([ev(src_ip="10.9.9.9") for _ in range(5)] + [ev(src_ip="10.1.1.1")])
    assert all("DET-006" in rule_ids(e) for e in events[:5])
    assert "DET-006" not in rule_ids(events[5])


def test_benign_event_is_observed_not_alerted():
    [e] = classify([ev(rule_name="dns event", severity=0)])
    assert e["decision"] == "observed" and e["classification"] == "informational" and e["matches"] == []


def test_upstream_block_alone_is_not_an_alert():
    [e] = classify([ev(source="modsecurity", intervention=True, http_status=403, rule_name="Inbound anomaly score")])
    assert e["decision"] == "observed" and "DET-007" in rule_ids(e)


def test_severity_is_max_of_source_and_rules():
    [e] = classify([ev(rule_name="nmap scan", severity=1)])
    assert e["detection_severity"] == 2
