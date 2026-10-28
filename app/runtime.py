"""Runtime policy state (mode and rate limits), persisted in the database."""
from __future__ import annotations

import threading
from dataclasses import asdict, dataclass

from sqlalchemy import select

from app.config import settings
from app.database import session_scope
from app.models import GatewaySetting

MODES = ("learning", "monitor", "enforce")

MODE_DESCRIPTIONS = {
    "learning": "Observe traffic and build endpoint profiles. Policy violations are recorded as observations; mandatory checks (authentication, payload size) still block.",
    "monitor": "Evaluate every rule and record violations as flagged, but forward the request. Mandatory checks still block.",
    "enforce": "Reject any request that violates a configured rule before it reaches the protected API.",
}


@dataclass
class PolicyState:
    mode: str
    rate_limit_requests: int
    rate_limit_window: int


class RuntimeState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = PolicyState(
            mode=settings.default_mode,
            rate_limit_requests=settings.rate_limit_requests,
            rate_limit_window=settings.rate_limit_window,
        )

    # -- accessors ---------------------------------------------------------
    @property
    def mode(self) -> str:
        return self._state.mode

    @property
    def rate_limit_requests(self) -> int:
        return self._state.rate_limit_requests

    @property
    def rate_limit_window(self) -> int:
        return self._state.rate_limit_window

    def snapshot(self) -> dict:
        return asdict(self._state)

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        with session_scope() as db:
            rows = {r.key: r.value for r in db.scalars(select(GatewaySetting))}
        with self._lock:
            if rows.get("mode") in MODES:
                self._state.mode = rows["mode"]
            for key in ("rate_limit_requests", "rate_limit_window"):
                if key in rows and rows[key].isdigit():
                    setattr(self._state, key, int(rows[key]))

    def update(self, **changes) -> dict:
        with self._lock:
            if "mode" in changes and changes["mode"] is not None:
                if changes["mode"] not in MODES:
                    raise ValueError("invalid mode")
                self._state.mode = changes["mode"]
            if changes.get("rate_limit_requests") is not None:
                self._state.rate_limit_requests = int(changes["rate_limit_requests"])
            if changes.get("rate_limit_window") is not None:
                self._state.rate_limit_window = int(changes["rate_limit_window"])
            snap = asdict(self._state)
        with session_scope() as db:
            for key, value in snap.items():
                row = db.get(GatewaySetting, key)
                if row is None:
                    db.add(GatewaySetting(key=key, value=str(value)))
                else:
                    row.value = str(value)
        return snap

    def reset_to_defaults(self) -> None:
        with self._lock:
            self._state = PolicyState(
                mode=settings.default_mode,
                rate_limit_requests=settings.rate_limit_requests,
                rate_limit_window=settings.rate_limit_window,
            )


runtime = RuntimeState()
