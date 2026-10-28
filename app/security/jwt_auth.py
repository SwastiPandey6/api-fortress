"""JWT validation.

Tokens are accepted only when they use the trusted algorithm, carry a valid
signature, are not expired, and contain the expected issuer and audience.
`alg: none` and algorithm-substitution tokens are rejected before decoding.
"""
from __future__ import annotations

import jwt

from app.config import settings
from app.security import Violation

REQUIRED_CLAIMS = ["exp", "iat", "sub"]


def _fail(rule_id: str, name: str, reason: str) -> Violation:
    return Violation(
        rule_id=rule_id,
        name=name,
        reason=reason,
        status_code=401,
        severity=2,
        category="authentication",
        mandatory=True,
        headers={"WWW-Authenticate": 'Bearer realm="api-fortress"'},
    )


def validate_authorization_header(header: str | None) -> tuple[dict | None, Violation | None]:
    if not header:
        return None, _fail("AUTH-001", "Missing token", "No Authorization header was supplied")

    scheme, _, token = header.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None, _fail("AUTH-002", "Invalid token", "Authorization header is not a Bearer token")

    try:
        unverified = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        return None, _fail("AUTH-002", "Invalid token", "Token is malformed")

    alg = str(unverified.get("alg", ""))
    if alg != settings.jwt_algorithm:
        return None, _fail("AUTH-002", "Invalid token", f"Untrusted signing algorithm '{alg or 'missing'}'")

    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": REQUIRED_CLAIMS},
            leeway=10,
        )
    except jwt.ExpiredSignatureError:
        return None, _fail("AUTH-003", "Expired token", "Token has expired")
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError, jwt.MissingRequiredClaimError) as exc:
        return None, _fail("AUTH-004", "Invalid claims", f"Token claims rejected: {exc}")
    except jwt.InvalidSignatureError:
        return None, _fail("AUTH-002", "Invalid token", "Token signature verification failed")
    except jwt.InvalidTokenError as exc:
        return None, _fail("AUTH-002", "Invalid token", f"Token rejected: {exc}")

    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        return None, _fail("AUTH-004", "Invalid claims", "Token subject is empty")
    return claims, None
