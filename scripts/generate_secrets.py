"""Print strong random values for the secrets in .env (paste them in before deploying)."""
import secrets

for name in ("JWT_SECRET", "GATEWAY_SHARED_SECRET", "ADMIN_SESSION_SECRET", "INGEST_TOKEN"):
    print(f"{name}={secrets.token_urlsafe(48)}")
print(f"ADMIN_PASSWORD={secrets.token_urlsafe(18)}")
