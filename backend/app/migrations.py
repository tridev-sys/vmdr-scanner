"""Additive schema migrations for SQLite.

`create_all` creates missing tables but never adds columns to existing ones, so a database
created before a model change needs its new columns added here. Each entry is idempotent.
For PostgreSQL, replace this with Alembic.
"""

from sqlalchemy import text
from sqlalchemy.engine import Engine

# table -> [(column, SQL type + default)]
ADDITIVE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "targets": [
        ("reachability", "VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN'"),
        ("consecutive_probe_failures", "INTEGER NOT NULL DEFAULT 0"),
        ("last_probed_at", "DATETIME"),
        ("last_probe_error", "VARCHAR(255)"),
        ("last_result", "VARCHAR(16)"),
        ("last_open_findings", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "scan_runs": [
        ("attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("unreachable_count", "INTEGER NOT NULL DEFAULT 0"),
        ("target_ids", "JSON"),
        ("cancel_requested", "BOOLEAN NOT NULL DEFAULT 0"),
        ("targets_scanned", "INTEGER NOT NULL DEFAULT 0"),
        ("chunks_total", "INTEGER NOT NULL DEFAULT 0"),
        ("chunks_done", "INTEGER NOT NULL DEFAULT 0"),
        ("cve_years", "INTEGER"),
        ("preset", "VARCHAR(16)"),
        ("rate_limit", "INTEGER"),
    ],
}


def migrate(engine: Engine) -> list[str]:
    """Add any missing columns. Returns the list of 'table.column' entries that were added."""
    if engine.dialect.name != "sqlite":
        return []
    added: list[str] = []
    with engine.begin() as conn:
        for table, columns in ADDITIVE_COLUMNS.items():
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if not existing:
                continue  # table does not exist yet; create_all will build it fresh
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    added.append(f"{table}.{name}")
    return added
