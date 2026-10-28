"""Protected demo API.

This service deliberately contains a Broken Object Level Authorization flaw:
`GET/PUT /records/{id}` authenticate the caller but never check that the
caller owns the record. API Fortress, sitting in front of it, is what stops
Alice from reading Bob's record. Do not copy this pattern into real code.

The API only accepts traffic that carries the gateway shared secret, so it
cannot be reached directly to bypass the gateway (except /health).
"""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from demo_api import db, settings
from demo_api.security import decode_token, issue_token, verify_password


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="API Fortress Demo API", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def require_gateway(request: Request, call_next):
    if settings.REQUIRE_GATEWAY and request.url.path != "/health":
        supplied = request.headers.get("x-gateway-secret", "")
        if not hmac.compare_digest(supplied.encode(), settings.GATEWAY_SHARED_SECRET.encode()):
            return JSONResponse({"detail": "Direct access is not permitted. Use the API gateway."}, status_code=403)
    return await call_next(request)


def require_gateway_secret(x_gateway_secret: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_gateway_secret.encode(), settings.GATEWAY_SHARED_SECRET.encode()):
        raise HTTPException(status_code=403, detail="Forbidden")


def current_user(authorization: str = Header(default="")) -> dict:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        claims = decode_token(token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"username": claims["sub"], "role": claims.get("role", "user")}


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RecordBody(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=5000)


@app.get("/health")
def health():
    return {"status": "ok", "service": "demo-api"}


@app.post("/auth/login")
def login(body: LoginBody):
    user = db.get_user(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, ttl = issue_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@app.get("/users/me")
def me(user: dict = Depends(current_user)):
    row = db.get_user(user["username"])
    return {"username": row["username"], "full_name": row["full_name"], "role": row["role"]}


@app.get("/records")
def my_records(user: dict = Depends(current_user)):
    return {"items": db.list_records(user["username"])}


@app.post("/records", status_code=201)
def create(body: RecordBody, user: dict = Depends(current_user)):
    return db.create_record(user["username"], body.title, body.content)


@app.get("/records/{record_id}")
def read_record(record_id: int, user: dict = Depends(current_user)):
    # INTENTIONAL FLAW: no ownership check (BOLA). The gateway enforces it.
    record = db.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@app.put("/records/{record_id}")
def update(record_id: int, body: RecordBody, user: dict = Depends(current_user)):
    # INTENTIONAL FLAW: no ownership check (BOLA). The gateway enforces it.
    if not db.get_record(record_id):
        raise HTTPException(status_code=404, detail="Record not found")
    return db.update_record(record_id, body.title, body.content)


# ---- private endpoints used only by the gateway --------------------------
@app.get("/internal/records/{record_id}/owner", dependencies=[Depends(require_gateway_secret)])
def record_owner(record_id: int):
    record = db.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"id": record_id, "owner": record["owner"]}


@app.post("/internal/reset", dependencies=[Depends(require_gateway_secret)])
def reset():
    db.init_db(reset=True)
    return {"reset": True}
