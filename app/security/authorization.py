"""Object-level authorization (BOLA protection).

For every protected resource route, the gateway resolves the owner of the
requested object through a private lookup endpoint on the backend and
compares it with the authenticated token subject. The backend lookup is
authenticated with the gateway shared secret and is never exposed publicly.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx

from app.config import settings
from app.security import Violation


@dataclass(frozen=True)
class ResourceRule:
    name: str
    pattern: re.Pattern[str]
    methods: frozenset[str]
    owner_lookup: str  # path template on the backend, e.g. /internal/records/{id}/owner

    def match(self, method: str, path: str) -> dict | None:
        if method.upper() not in self.methods:
            return None
        m = self.pattern.match(path)
        return m.groupdict() if m else None


PROTECTED_RESOURCES: list[ResourceRule] = [
    ResourceRule(
        name="record",
        pattern=re.compile(r"^/records/(?P<id>\d+)/?$"),
        methods=frozenset({"GET", "PUT", "PATCH", "DELETE"}),
        owner_lookup="/internal/records/{id}/owner",
    ),
]

PRIVILEGED_ROLES = {"admin"}
_MISSING = object()


class OwnershipChecker:
    def __init__(self, ttl_seconds: float = 30.0) -> None:
        self._cache: dict[str, tuple[object, float]] = {}
        self._ttl = ttl_seconds

    def clear(self) -> None:
        self._cache.clear()

    def describe(self) -> list[dict]:
        return [
            {"resource": r.name, "pattern": r.pattern.pattern, "methods": sorted(r.methods)}
            for r in PROTECTED_RESOURCES
        ]

    async def _lookup_owner(self, client: httpx.AsyncClient, lookup_path: str):
        cached = self._cache.get(lookup_path)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0]
        resp = await client.get(
            lookup_path,
            headers={"X-Gateway-Secret": settings.gateway_shared_secret},
            timeout=settings.backend_timeout,
        )
        if resp.status_code == 404:
            return _MISSING  # not cached: the object may be created later
        if resp.status_code != 200:
            raise RuntimeError(f"owner lookup returned HTTP {resp.status_code}")
        owner = resp.json().get("owner")
        self._cache[lookup_path] = (owner, now + self._ttl)
        return owner

    async def check(self, method: str, path: str, claims: dict, client: httpx.AsyncClient) -> Violation | None:
        for rule in PROTECTED_RESOURCES:
            params = rule.match(method, path)
            if params is None:
                continue
            if claims.get("role") in PRIVILEGED_ROLES:
                return None
            lookup_path = rule.owner_lookup.format(**params)
            try:
                owner = await self._lookup_owner(client, lookup_path)
            except Exception as exc:  # fail closed
                return Violation(
                    rule_id="AUTHZ-002",
                    name="Authorization unverifiable",
                    reason=f"Ownership of {rule.name} could not be verified ({exc.__class__.__name__})",
                    status_code=503,
                    severity=2,
                    category="authorization",
                    mandatory=True,
                )
            if owner is _MISSING:
                return None  # let the backend return its own 404
            if owner != claims.get("sub"):
                return Violation(
                    rule_id="AUTHZ-001",
                    name="Object ownership violation",
                    reason=f"User '{claims.get('sub')}' attempted to access {rule.name} {params.get('id')} owned by another user",
                    status_code=403,
                    severity=3,
                    category="broken_object_level_authorization",
                    mandatory=False,
                )
            return None
        return None


ownership = OwnershipChecker()
