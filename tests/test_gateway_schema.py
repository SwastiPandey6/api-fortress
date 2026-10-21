from sqlalchemy import inspect
from app import models


def test_schema_and_defaults_created():
    models.init_db()
    models.init_db()  # idempotent
    assert {"events", "config", "rules"} <= set(inspect(models.engine).get_table_names())
    with models.SessionLocal() as db:
        assert db.get(models.Config, "mode").value in models.MODES
        assert db.query(models.Rule).count() == len(models.DEFAULT_RULES)


def test_can_store_event():
    models.init_db()
    with models.SessionLocal() as db:
        db.add(models.Event(client_ip="127.0.0.1", method="GET", path="/health",
                            status_code=200, decision="allow", mode="monitor"))
        db.commit()
        assert db.query(models.Event).count() >= 1
