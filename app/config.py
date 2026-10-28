"""Gateway configuration.

All values are read from environment variables (or a local `.env` file in the
project root). Defaults are suitable for local development only; the gateway
refuses to start with development secrets when APP_ENV=production.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def load_env_file(path: Path = BASE_DIR / ".env") -> None:
    """Minimal .env loader (no external dependency). Real env vars win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

DEV_JWT_SECRET = "dev-jwt-secret-change-me-0123456789abcdef"
DEV_SHARED_SECRET = "dev-gateway-shared-secret-change-me"
DEV_SESSION_SECRET = "dev-admin-session-secret-change-me-0123456789"
DEV_ADMIN_PASSWORD = "ChangeMe!2026"


def _str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _default_db_url() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(DATA_DIR / 'fortress.db').as_posix()}"


@dataclass
class Settings:
    app_env: str = field(default_factory=lambda: _str("APP_ENV", "development"))

    # Upstream (protected) API
    backend_url: str = field(default_factory=lambda: _str("BACKEND_URL", "http://127.0.0.1:9000").rstrip("/"))
    backend_timeout: float = field(default_factory=lambda: _float("BACKEND_TIMEOUT_SECONDS", 10.0))
    gateway_shared_secret: str = field(default_factory=lambda: _str("GATEWAY_SHARED_SECRET", DEV_SHARED_SECRET))

    # URL the gateway uses to call itself (attack lab)
    self_url: str = field(default_factory=lambda: _str("GATEWAY_SELF_URL", "http://127.0.0.1:8000").rstrip("/"))

    # Storage
    database_url: str = field(default_factory=lambda: _str("DATABASE_URL", "") or _default_db_url())

    # Token validation (must match the API that issues tokens)
    jwt_secret: str = field(default_factory=lambda: _str("JWT_SECRET", DEV_JWT_SECRET))
    jwt_algorithm: str = field(default_factory=lambda: _str("JWT_ALGORITHM", "HS256"))
    jwt_issuer: str = field(default_factory=lambda: _str("JWT_ISSUER", "api-fortress-demo"))
    jwt_audience: str = field(default_factory=lambda: _str("JWT_AUDIENCE", "demo-api"))

    # Policy defaults (can be changed at runtime from the dashboard)
    default_mode: str = field(default_factory=lambda: _str("GATEWAY_MODE", "enforce").lower())
    rate_limit_requests: int = field(default_factory=lambda: _int("RATE_LIMIT_REQUESTS", 30))
    rate_limit_window: int = field(default_factory=lambda: _int("RATE_LIMIT_WINDOW_SECONDS", 60))
    max_body_bytes: int = field(default_factory=lambda: _int("MAX_BODY_BYTES", 1_048_576))
    public_paths: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            p.strip() for p in _str("PUBLIC_PATHS", "/auth/login,/health").split(",") if p.strip()
        )
    )
    trust_proxy_headers: bool = field(default_factory=lambda: _bool("TRUST_PROXY_HEADERS", False))

    # Admin console
    admin_username: str = field(default_factory=lambda: _str("ADMIN_USERNAME", "admin"))
    admin_password: str = field(default_factory=lambda: _str("ADMIN_PASSWORD", DEV_ADMIN_PASSWORD))
    admin_session_secret: str = field(default_factory=lambda: _str("ADMIN_SESSION_SECRET", DEV_SESSION_SECRET))
    session_ttl_minutes: int = field(default_factory=lambda: _int("SESSION_TTL_MINUTES", 480))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", False))

    # Log shipping (machine-to-machine ingestion). Empty disables the endpoint.
    ingest_token: str = field(default_factory=lambda: _str("INGEST_TOKEN", ""))
    max_upload_bytes: int = field(default_factory=lambda: _int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    def validate(self) -> None:
        if self.default_mode not in {"learning", "monitor", "enforce"}:
            raise RuntimeError(f"GATEWAY_MODE must be learning, monitor or enforce (got {self.default_mode!r})")
        if not self.is_production:
            return
        problems = []
        if self.jwt_secret == DEV_JWT_SECRET or len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET (use 32+ random characters)")
        if self.gateway_shared_secret == DEV_SHARED_SECRET or len(self.gateway_shared_secret) < 24:
            problems.append("GATEWAY_SHARED_SECRET")
        if self.admin_session_secret == DEV_SESSION_SECRET or len(self.admin_session_secret) < 32:
            problems.append("ADMIN_SESSION_SECRET")
        if self.admin_password == DEV_ADMIN_PASSWORD or len(self.admin_password) < 12:
            problems.append("ADMIN_PASSWORD (12+ characters)")
        if problems:
            raise RuntimeError(
                "Refusing to start in production with insecure settings: " + ", ".join(problems)
            )


settings = Settings()
