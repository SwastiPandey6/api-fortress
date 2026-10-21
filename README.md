# API Fortress

Day 1 status: demo API (the protected target), gateway database schema, tests.

## Setup

**Windows (PowerShell)**
```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
**Linux / macOS**
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the tests
```
python -m pytest -q
```

## Run the demo API (port 9000)
```
uvicorn demo_api.main:app --port 9000
```
Test users: `alice / alice-pass`, `bob / bob-pass`. Interactive docs: http://127.0.0.1:9000/docs

The demo API is **deliberately vulnerable** (`DEMO_VULNERABLE=true`, default):
- `GET /records/{id}` has no ownership check (BOLA/IDOR)
- `PATCH /me` accepts `role` (mass assignment)

The gateway (Days 2-6) must block these. Set `DEMO_VULNERABLE=false` for the safe version.
Never expose the demo API publicly; clients must reach it only through the gateway.

## Layout
- `demo_api/` target application (port 9000)
- `app/` gateway (port 8000, from Day 2); `app/models.py` holds the events / config / rules schema
- `tests/` pytest suite
