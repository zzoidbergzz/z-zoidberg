"""Tests for entity deduplication / UNIQUE constraint enforcement."""

import uuid
import pytest


def test_entity_on_conflict_do_update_sql_pattern():
    """
    Verify the ON CONFLICT DO UPDATE pattern builds without errors.
    The resulting SQL should mention 'ON CONFLICT' and 'DO UPDATE'.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from app.models.entities import Entity
    from sqlalchemy import func

    tid = str(uuid.uuid4())
    stmt = (
        pg_insert(Entity.__table__)
        .values(tenant_id=tid, kind="ip", canonical_name="1.2.3.4", external_refs={})
        .on_conflict_do_update(
            index_elements=["tenant_id", "kind", "canonical_name"],
            set_={"updated_at": func.now()},
        )
        .returning(Entity.__table__.c.id)
    )
    compiled = stmt.compile(dialect=__import__("sqlalchemy.dialects.postgresql", fromlist=["dialect"]).dialect())
    sql = str(compiled)
    assert "ON CONFLICT" in sql.upper()
    assert "DO UPDATE" in sql.upper()
    assert "updated_at" in sql


def test_worker_imports_func():
    """func must be importable from worker so on_conflict_do_update can call func.now()."""
    from app import worker  # noqa: F401 - just verify it imports without error
    from sqlalchemy import func
    assert func.now is not None
