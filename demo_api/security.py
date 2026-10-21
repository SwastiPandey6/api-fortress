import hashlib, hmac, os, time
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me-32-bytes-minimum!!")
JWT_ALG = "HS256"
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "900"))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, _ = stored.split("$")
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), stored)


def make_token(user_id: int, username: str, role: str) -> str:
    now = int(time.time())
    claims = {"sub": str(user_id), "username": username, "role": role, "iat": now, "exp": now + TOKEN_TTL}
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"require": ["exp", "sub"]})
