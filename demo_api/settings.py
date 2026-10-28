"""Demo API configuration (shares JWT/secret settings with the gateway via env)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file(path: Path = BASE_DIR / ".env") -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env_file()

JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt-secret-change-me-0123456789abcdef")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "api-fortress-demo")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "demo-api")
TOKEN_TTL_MINUTES = int(os.getenv("TOKEN_TTL_MINUTES", "30"))
GATEWAY_SHARED_SECRET = os.getenv("GATEWAY_SHARED_SECRET", "dev-gateway-shared-secret-change-me")
# When true the API rejects any request that did not come through the gateway.
REQUIRE_GATEWAY = os.getenv("REQUIRE_GATEWAY", "true").strip().lower() in {"1", "true", "yes", "on"}
DB_PATH = Path(os.getenv("DEMO_DB_PATH", str(BASE_DIR / "data" / "demo_api.db")))
