"""Schema-level checks for the event store."""
from sqlalchemy import inspect

from app.database import engine, init_db


def test_tables_and_columns_exist():
    init_db()
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert {"security_events", "ingest_batches", "gateway_settings", "endpoint_profiles"} <= tables
    cols = {c["name"] for c in insp.get_columns("security_events")}
    for required in ("origin", "source", "decision", "classification", "rule_id", "reason", "matches",
                     "severity", "mode", "path", "status_code", "client_ip", "username", "raw", "batch_id"):
        assert required in cols, required


def test_origin_column_is_indexed():
    insp = inspect(engine)
    indexed = {c for ix in insp.get_indexes("security_events") for c in ix["column_names"]}
    assert "origin" in indexed and "decision" in indexed
