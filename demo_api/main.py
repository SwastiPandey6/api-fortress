"""Demo API: the *protected target* behind API Fortress.

DEMO_VULNERABLE=true (default) keeps two deliberate weaknesses so the gateway has
something real to defend and the security tester has something real to find:
  1. BOLA / IDOR: GET /records/{id} does not check record ownership.
  2. Mass assignment: PATCH /me accepts a client-supplied `role`.
Set DEMO_VULNERABLE=false to run the safe version (used to prove the tests can tell them apart).
Never deploy this app publicly. Keep it reachable only through the gateway.
"""
import os
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
import jwt

from .db import Base, Record, SessionLocal, User, engine
from .security import decode_token, hash_password, make_token, verify_password


def vulnerable() -> bool:
    return os.getenv("DEMO_VULNERABLE", "true").lower() == "true"


def seed():
    """Idempotent seed: two normal users with separate records."""
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.query(User).count():
            return
        alice = User(username="alice", password_hash=hash_password("alice-pass"), email="alice@example.test")
        bob = User(username="bob", password_hash=hash_password("bob-pass"), email="bob@example.test")
        db.add_all([alice, bob]); db.flush()
        db.add_all([
            Record(owner_id=alice.id, title="Alice - medical note", content="Alice private data #1"),
            Record(owner_id=alice.id, title="Alice - bank note", content="Alice private data #2"),
            Record(owner_id=bob.id, title="Bob - medical note", content="Bob private data #1"),
            Record(owner_id=bob.id, title="Bob - bank note", content="Bob private data #2"),
        ])
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed()
    yield


app = FastAPI(title="API Fortress demo API", lifespan=lifespan)


def get_db():
    with SessionLocal() as db:
        yield db


def current_user(authorization: str | None = Header(default=None), db=Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        claims = decode_token(authorization.split(" ", 1)[1])
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid or expired token")
    user = db.get(User, int(claims["sub"]))
    if not user:
        raise HTTPException(401, "unknown user")
    return user


class LoginIn(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    email: str | None = None
    role: str | None = None  # only honoured in vulnerable mode


@app.get("/health")
def health():
    return {"status": "ok", "vulnerable": vulnerable()}


@app.post("/login")
def login(body: LoginIn, db=Depends(get_db)):
    user = db.query(User).filter_by(username=body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "bad credentials")
    return {"access_token": make_token(user.id, user.username, user.role), "token_type": "bearer"}


@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role, "email": user.email}


@app.patch("/me")
def update_me(body: ProfileUpdate, user: User = Depends(current_user), db=Depends(get_db)):
    if body.email is not None:
        user.email = body.email
    if body.role is not None and vulnerable():
        user.role = body.role  # deliberate mass-assignment flaw
    db.add(user); db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "email": user.email}


@app.get("/records")
def list_records(user: User = Depends(current_user), db=Depends(get_db)):
    rows = db.query(Record).filter_by(owner_id=user.id).all()
    return [{"id": r.id, "title": r.title} for r in rows]


@app.get("/records/{record_id}")
def get_record(record_id: int, user: User = Depends(current_user), db=Depends(get_db)):
    rec = db.get(Record, record_id)
    if not rec:
        raise HTTPException(404, "record not found")
    if not vulnerable() and rec.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "not your record")  # the correct check, skipped in vulnerable mode
    return {"id": rec.id, "owner_id": rec.owner_id, "title": rec.title, "content": rec.content}
