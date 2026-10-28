"""Database models.

`SecurityEvent` is the single store for both live gateway decisions
(origin="gateway") and findings from imported security logs
(origin="imported"). The `origin` and `source` columns are always set so the
two can never be confused: an imported alert is never presented as a request
that API Fortress itself blocked.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class IngestBatch(Base):
    __tablename__ = "ingest_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(16), default="upload")  # upload | push
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    records_parsed: Mapped[int] = mapped_column(Integer, default=0)
    records_skipped: Mapped[int] = mapped_column(Integer, default=0)
    records_failed: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[str] = mapped_column(Text, default="[]")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    origin: Mapped[str] = mapped_column(String(16), index=True)  # gateway | imported
    source: Mapped[str] = mapped_column(String(32), index=True)  # api_gateway | wazuh | suricata | modsecurity
    event_type: Mapped[str] = mapped_column(String(64), default="request")
    decision: Mapped[str] = mapped_column(String(16), index=True)  # allowed|blocked|flagged|observed|alert|error
    classification: Mapped[str] = mapped_column(String(48), default="none", index=True)

    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    matches: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of matched rules
    severity: Mapped[int] = mapped_column(Integer, default=0, index=True)  # 0 info .. 4 critical

    mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    method: Mapped[str | None] = mapped_column(String(12), nullable=True)
    path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)

    batch_id: Mapped[int | None] = mapped_column(ForeignKey("ingest_batches.id", ondelete="CASCADE"), nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_events_origin_created", "origin", "created_at"),)


class GatewaySetting(Base):
    __tablename__ = "gateway_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class EndpointProfile(Base):
    """Observations collected in Learning mode."""

    __tablename__ = "endpoint_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    method: Mapped[str] = mapped_column(String(12))
    path_template: Mapped[str] = mapped_column(String(512))
    hits: Mapped[int] = mapped_column(Integer, default=0)
    distinct_users: Mapped[str] = mapped_column(Text, default="[]")
    status_codes: Mapped[str] = mapped_column(Text, default="{}")
    max_body_bytes: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (Index("ux_profile", "method", "path_template", unique=True),)
