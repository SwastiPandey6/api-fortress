"""Request content inspection for common injection patterns.

These signatures are intentionally conservative. They are a defence-in-depth
layer, not a replacement for parameterised queries and output encoding in the
protected application.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from app.security import Violation

SIGNATURES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "sql_injection",
        "SQL injection pattern",
        re.compile(
            r"(\bunion\b\s+(all\s+)?select\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\b\s+1\s*=\s*1\b|;\s*drop\s+table\b"
            r"|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|'\s*;\s*--|'\s*--)",
            re.IGNORECASE,
        ),
    ),
    (
        "cross_site_scripting",
        "Cross-site scripting pattern",
        re.compile(r"(<\s*script\b|javascript\s*:|\bon(error|load|mouseover)\s*=|<\s*iframe\b|<\s*svg[^>]*on\w+\s*=)", re.IGNORECASE),
    ),
    (
        "path_traversal",
        "Path traversal pattern",
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|\bwin\.ini\b|\bboot\.ini\b)", re.IGNORECASE),
    ),
    (
        "command_injection",
        "OS command injection pattern",
        re.compile(r"([;&|]\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b|`[^`]{1,80}`|\$\([^)]{1,80}\))", re.IGNORECASE),
    ),
]

MAX_INSPECT_BYTES = 64 * 1024


def _decode(value: str, rounds: int = 2) -> str:
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def inspect_request(raw_path: str, query: str, body: bytes, content_type: str = "") -> Violation | None:
    parts = [_decode(raw_path), _decode(query)]
    if body and not content_type.startswith(("multipart/", "application/octet-stream", "image/")):
        parts.append(body[:MAX_INSPECT_BYTES].decode("utf-8", errors="ignore"))
    haystack = "\n".join(p for p in parts if p)
    for category, label, pattern in SIGNATURES:
        match = pattern.search(haystack)
        if match:
            snippet = match.group(0)[:60]
            return Violation(
                rule_id="REQ-001",
                name="Suspicious input",
                reason=f"{label} detected: {snippet!r}",
                status_code=400,
                severity=3,
                category=category,
                mandatory=False,
            )
    return None
