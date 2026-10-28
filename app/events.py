"""Event recording and the read-side queries used by the dashboard."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import delete, func, or_, select

from app.database import session_scope
from app.models import EndpointProfile, IngestBatch, SecurityEvent, utcnow

SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


# --------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------
def record_gateway_event(data: dict) -> int:
    with session_scope() as db:
        ev = SecurityEvent(origin="gateway", source="api_gateway", event_time=utcnow(), **data)
        db.add(ev)
        db.flush()
        return ev.id


def save_import(batch: dict, events: list[dict]) -> dict:
    with session_scope() as db:
        b = IngestBatch(**batch)
        db.add(b)
        db.flush()
        db.add_all(SecurityEvent(origin="imported", batch_id=b.id, **e) for e in events)
        db.flush()
        return batch_to_dict(b)


_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F-]{32,36})$")


def path_template(path: str) -> str:
    segments = []
    for seg in path.split("/"):
        if _ID_SEGMENT.match(seg):
            segments.append("{id}")
        else:
            segments.append(seg)
    return "/".join(segments) or "/"


def record_profile(method: str, path: str, user: str | None, status: int | None, body_len: int) -> None:
    template = path_template(path)
    with session_scope() as db:
        prof = db.scalar(
            select(EndpointProfile).where(EndpointProfile.method == method, EndpointProfile.path_template == template)
        )
        if prof is None:
            prof = EndpointProfile(method=method, path_template=template, hits=0, distinct_users="[]", status_codes="{}")
            db.add(prof)
        prof.hits = (prof.hits or 0) + 1
        users = set(json.loads(prof.distinct_users or "[]"))
        if user:
            users.add(user)
        prof.distinct_users = json.dumps(sorted(users)[:200])
        codes = json.loads(prof.status_codes or "{}")
        if status is not None:
            codes[str(status)] = codes.get(str(status), 0) + 1
        prof.status_codes = json.dumps(codes)
        prof.max_body_bytes = max(prof.max_body_bytes or 0, body_len)
        prof.last_seen = utcnow()


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------
def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def event_to_dict(e: SecurityEvent, include_raw: bool = False) -> dict:
    out = {
        "id": e.id,
        "created_at": _iso(e.created_at),
        "event_time": _iso(e.event_time),
        "origin": e.origin,
        "source": e.source,
        "event_type": e.event_type,
        "decision": e.decision,
        "classification": e.classification,
        "rule_id": e.rule_id,
        "rule_name": e.rule_name,
        "reason": e.reason,
        "severity": e.severity,
        "severity_label": SEVERITY_LABELS.get(e.severity, "info"),
        "mode": e.mode,
        "request_id": e.request_id,
        "method": e.method,
        "path": e.path,
        "status_code": e.status_code,
        "latency_ms": e.latency_ms,
        "client_ip": e.client_ip,
        "dest_ip": e.dest_ip,
        "username": e.username,
        "batch_id": e.batch_id,
        "matches": json.loads(e.matches or "[]"),
    }
    if include_raw:
        try:
            out["raw"] = json.loads(e.raw) if e.raw else None
        except (TypeError, ValueError):
            out["raw"] = e.raw
    return out


def batch_to_dict(b: IngestBatch) -> dict:
    return {
        "id": b.id,
        "created_at": _iso(b.created_at),
        "filename": b.filename,
        "source": b.source,
        "channel": b.channel,
        "records_total": b.records_total,
        "records_parsed": b.records_parsed,
        "records_skipped": b.records_skipped,
        "records_failed": b.records_failed,
        "alerts": b.alerts,
        "errors": json.loads(b.errors or "[]"),
    }


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------
def _apply_filters(stmt, f: dict):
    if f.get("origin"):
        stmt = stmt.where(SecurityEvent.origin == f["origin"])
    if f.get("source"):
        stmt = stmt.where(SecurityEvent.source == f["source"])
    if f.get("decision"):
        stmt = stmt.where(SecurityEvent.decision.in_(f["decision"].split(",")))
    if f.get("classification"):
        stmt = stmt.where(SecurityEvent.classification == f["classification"])
    if f.get("rule_id"):
        stmt = stmt.where(SecurityEvent.rule_id == f["rule_id"])
    if f.get("min_severity") is not None:
        stmt = stmt.where(SecurityEvent.severity >= int(f["min_severity"]))
    if f.get("batch_id"):
        stmt = stmt.where(SecurityEvent.batch_id == int(f["batch_id"]))
    if f.get("q"):
        like = f"%{f['q']}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.path.ilike(like),
                SecurityEvent.reason.ilike(like),
                SecurityEvent.rule_name.ilike(like),
                SecurityEvent.client_ip.ilike(like),
                SecurityEvent.username.ilike(like),
                SecurityEvent.rule_id.ilike(like),
            )
        )
    return stmt


def query_events(filters: dict, limit: int = 50, offset: int = 0) -> tuple[int, list[dict]]:
    with session_scope() as db:
        base = _apply_filters(select(SecurityEvent), filters)
        total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
        if filters.get("origin") == "imported":
            order = (SecurityEvent.event_time.is_(None), SecurityEvent.event_time.desc(), SecurityEvent.id.desc())
        else:
            order = (SecurityEvent.id.desc(),)
        rows = db.scalars(base.order_by(*order).limit(limit).offset(offset)).all()
        return total, [event_to_dict(r) for r in rows]


def iter_events(filters: dict, max_rows: int = 50000):
    with session_scope() as db:
        stmt = _apply_filters(select(SecurityEvent), filters).order_by(SecurityEvent.id.desc()).limit(max_rows)
        for row in db.scalars(stmt):
            yield event_to_dict(row)


def get_event(event_id: int) -> dict | None:
    with session_scope() as db:
        e = db.get(SecurityEvent, event_id)
        return event_to_dict(e, include_raw=True) if e else None


def overview() -> dict:
    with session_scope() as db:
        def count(*conds):
            return db.scalar(select(func.count(SecurityEvent.id)).where(*conds)) or 0

        g = SecurityEvent.origin == "gateway"
        i = SecurityEvent.origin == "imported"
        since = utcnow() - timedelta(hours=24)

        decisions = dict(
            db.execute(
                select(SecurityEvent.decision, func.count()).where(g).group_by(SecurityEvent.decision)
            ).all()
        )
        total = sum(decisions.values())
        latency = db.scalar(select(func.avg(SecurityEvent.latency_ms)).where(g, SecurityEvent.created_at >= since))

        top_rules = db.execute(
            select(SecurityEvent.rule_id, SecurityEvent.rule_name, func.count().label("n"))
            .where(g, SecurityEvent.rule_id.is_not(None))
            .group_by(SecurityEvent.rule_id, SecurityEvent.rule_name)
            .order_by(func.count().desc())
            .limit(6)
        ).all()

        imported_sev = dict(
            db.execute(select(SecurityEvent.severity, func.count()).where(i).group_by(SecurityEvent.severity)).all()
        )
        imported_cls = db.execute(
            select(SecurityEvent.classification, func.count())
            .where(i, SecurityEvent.classification != "informational")
            .group_by(SecurityEvent.classification)
            .order_by(func.count().desc())
        ).all()
        imported_src = dict(
            db.execute(select(SecurityEvent.source, func.count()).where(i).group_by(SecurityEvent.source)).all()
        )
        top_ips = db.execute(
            select(SecurityEvent.client_ip, func.count())
            .where(SecurityEvent.decision.in_(["blocked", "flagged", "alert"]), SecurityEvent.client_ip.is_not(None))
            .group_by(SecurityEvent.client_ip)
            .order_by(func.count().desc())
            .limit(5)
        ).all()

        return {
            "gateway": {
                "total": total,
                "allowed": decisions.get("allowed", 0),
                "blocked": decisions.get("blocked", 0),
                "flagged": decisions.get("flagged", 0),
                "observed": decisions.get("observed", 0),
                "errors": decisions.get("error", 0),
                "last_24h": count(g, SecurityEvent.created_at >= since),
                "blocked_24h": count(g, SecurityEvent.decision == "blocked", SecurityEvent.created_at >= since),
                "avg_latency_ms": round(latency, 1) if latency else None,
                "block_rate": round(100 * decisions.get("blocked", 0) / total, 1) if total else 0.0,
                "top_rules": [{"rule_id": r, "rule_name": n, "count": c} for r, n, c in top_rules],
            },
            "imported": {
                "total": sum(imported_src.values()),
                "alerts": count(i, SecurityEvent.decision == "alert"),
                "high_or_critical": count(i, SecurityEvent.severity >= 3),
                "by_severity": {SEVERITY_LABELS[k]: imported_sev.get(k, 0) for k in range(5)},
                "by_classification": [{"classification": c, "count": n} for c, n in imported_cls],
                "by_source": imported_src,
                "batches": db.scalar(select(func.count(IngestBatch.id))) or 0,
            },
            "top_sources": [{"ip": ip, "count": n} for ip, n in top_ips],
        }


def timeline(range_key: str = "60m") -> dict:
    if range_key == "24h":
        span, step, fmt = timedelta(hours=24), timedelta(hours=1), "%H:00"
    elif range_key == "6h":
        span, step, fmt = timedelta(hours=6), timedelta(minutes=15), "%H:%M"
    else:
        span, step, fmt = timedelta(minutes=60), timedelta(minutes=2), "%H:%M"
    now = utcnow()
    step_s = step.total_seconds()
    start_epoch = (now - span).timestamp()
    start_epoch -= start_epoch % step_s
    start = datetime.fromtimestamp(start_epoch)
    n = int(span.total_seconds() // step_s) + 1
    buckets = [defaultdict(int) for _ in range(n)]

    with session_scope() as db:
        rows = db.execute(
            select(SecurityEvent.created_at, SecurityEvent.decision).where(
                SecurityEvent.origin == "gateway", SecurityEvent.created_at >= start
            )
        ).all()
    for created, decision in rows:
        idx = int((created - start).total_seconds() // step_s)
        if 0 <= idx < n:
            buckets[idx][decision] += 1

    out = []
    for k, b in enumerate(buckets):
        t = start + step * k
        out.append(
            {
                "t": t.isoformat(timespec="seconds") + "Z",
                "label": t.strftime(fmt),
                "allowed": b["allowed"],
                "flagged": b["flagged"] + b["observed"],
                "blocked": b["blocked"],
                "errors": b["error"],
            }
        )
    return {"range": range_key, "step_seconds": int(step_s), "buckets": out}


def list_batches(limit: int = 50) -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(select(IngestBatch).order_by(IngestBatch.id.desc()).limit(limit)).all()
        return [batch_to_dict(b) for b in rows]


def list_profiles() -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(select(EndpointProfile).order_by(EndpointProfile.hits.desc())).all()
        return [
            {
                "method": p.method,
                "path_template": p.path_template,
                "hits": p.hits,
                "distinct_users": len(json.loads(p.distinct_users or "[]")),
                "status_codes": json.loads(p.status_codes or "{}"),
                "max_body_bytes": p.max_body_bytes,
                "first_seen": _iso(p.first_seen),
                "last_seen": _iso(p.last_seen),
            }
            for p in rows
        ]


def clear_events(origin: str | None) -> int:
    with session_scope() as db:
        stmt = delete(SecurityEvent)
        if origin:
            stmt = stmt.where(SecurityEvent.origin == origin)
        n = db.execute(stmt).rowcount or 0
        if origin in (None, "imported"):
            db.execute(delete(IngestBatch))
        if origin in (None, "gateway"):
            db.execute(delete(EndpointProfile))
        return n
