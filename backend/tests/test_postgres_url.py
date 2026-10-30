"""Engine selection for SQLite vs PostgreSQL URLs. No PostgreSQL server is needed,
except for the one test that is skipped unless VMDR_TEST_POSTGRES_URL is set and reachable."""

import os

import pytest
import sqlalchemy as sa

from app import config


@pytest.fixture()
def set_url(monkeypatch):
    def _set(url: str):
        monkeypatch.setenv("VMDR_DATABASE_URL", url)
        config.get_settings.cache_clear()

    yield _set
    monkeypatch.undo()
    config.get_settings.cache_clear()


def _connect_listener_names(engine) -> set[str]:
    return {getattr(fn, "__name__", "") for fn in engine.pool.dispatch.connect.listeners}


def _make_engine():
    from app import db
    return db._make_engine()


def test_sqlite_url_gets_wal_pragmas(set_url, tmp_path):
    set_url(f"sqlite:///{tmp_path}/pragma.db")
    engine = _make_engine()
    assert engine.dialect.name == "sqlite"
    assert "_sqlite_pragmas" in _connect_listener_names(engine)
    with engine.connect() as conn:
        assert conn.execute(sa.text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(sa.text("PRAGMA foreign_keys")).scalar() == 1
    engine.dispose()


def test_postgres_url_has_no_sqlite_pragmas(set_url):
    set_url("postgresql+psycopg://vmdr:unused@localhost:5432/vmdr")
    engine = _make_engine()  # no connection is opened by create_engine
    assert engine.dialect.name == "postgresql"
    assert engine.dialect.driver == "psycopg"
    assert "_sqlite_pragmas" not in _connect_listener_names(engine)
    assert engine.pool._pre_ping is True
    engine.dispose()


def test_postgres_init_db_against_live_server(set_url):
    url = os.environ.get("VMDR_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("needs a live PostgreSQL server; set VMDR_TEST_POSTGRES_URL to run")
    set_url(url)
    engine = _make_engine()
    try:
        with engine.connect():
            pass
    except sa.exc.OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at VMDR_TEST_POSTGRES_URL: {exc.orig}")
    from sqlmodel import SQLModel
    from app import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    assert "targets" in sa.inspect(engine).get_table_names()
    engine.dispose()
