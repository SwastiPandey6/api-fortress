"""Glue between the parser, detection engine and event store."""
from __future__ import annotations

import json
from collections import Counter

from app import events
from app.detection import classify, to_db_record
from app.log_parser import parse_content


def ingest(content: bytes | str, filename: str, source_hint: str = "auto", channel: str = "upload") -> dict:
    parsed = parse_content(content, source_hint)
    classified = classify(parsed.events)
    records = [to_db_record(e) for e in classified]

    sources = Counter(r["source"] for r in records)
    batch_source = sources.most_common(1)[0][0] if len(sources) == 1 else ("mixed" if sources else source_hint)
    alerts = sum(1 for r in records if r["decision"] == "alert")

    batch = events.save_import(
        {
            "filename": filename[:255],
            "source": batch_source,
            "channel": channel,
            "records_total": parsed.total,
            "records_parsed": len(records),
            "records_skipped": parsed.skipped,
            "records_failed": parsed.failed,
            "alerts": alerts,
            "errors": json.dumps(parsed.errors),
        },
        records,
    )
    batch["classifications"] = dict(Counter(r["classification"] for r in records))
    batch["severity"] = dict(Counter(events.SEVERITY_LABELS[r["severity"]] for r in records))
    return batch
