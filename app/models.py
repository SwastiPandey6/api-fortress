"""Gateway schema, agreed on Day 1 so later days only add rows, not tables.

events  - one row per request that passed through the gateway (the dashboard reads this)
config  - key/value gateway settings (mode, thresholds)
rules   - policy rules (Day 6 verified-fix workflow enables/disables these)
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
import os

GATEWAY_DB_URL = os.getenv("GATEWAY_DB_URL", "sqlite:///data/gateway.db")
engine = create_engine(GATEWAY_DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

MODES = ("learning", "monitor", "enforce")


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    client_ip: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500), index=True)
    user_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(20))        # allow | block | would_block
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    mode: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)   # Day 7 audit chain
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Config(Base):
    __tablename__ = "config"
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


DEFAULT_CONFIG = {"mode": "monitor", "rate_limit_per_min": "60", "login_rate_limit_per_min": "5"}
DEFAULT_RULES = {
    "jwt-required": "Reject requests without a valid, unexpired JWT",
    "bola-records": "Users may only read their own /records/{id}",
    "mass-assignment": "Strip/deny protected fields (role) on PATCH /me",
    "rate-limit": "Per-IP request rate limit",
    "login-rate-limit": "Stricter per-IP limit on POST /login",
}


def init_db():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        for k, v in DEFAULT_CONFIG.items():
            if not db.get(Config, k):
                db.add(Config(key=k, value=v))
        for rid, desc in DEFAULT_RULES.items():
            if not db.get(Rule, rid):
                db.add(Rule(id=rid, description=desc, enabled=True))
        db.commit()
