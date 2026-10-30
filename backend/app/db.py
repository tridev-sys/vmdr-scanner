from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings


def _make_engine():
    url = get_settings().database_url
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            # WAL lets the API read while the worker writes. Migrating to PostgreSQL only
            # requires changing DATABASE_URL and replacing create_all with Alembic migrations.
            for pragma in ("journal_mode=WAL", "synchronous=NORMAL", "foreign_keys=ON", "busy_timeout=30000"):
                cur.execute(f"PRAGMA {pragma}")
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True)


engine = _make_engine()


def init_db() -> None:
    from app import models  # noqa: F401  (registers tables)
    from app.migrations import migrate

    SQLModel.metadata.create_all(engine)
    migrate(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
