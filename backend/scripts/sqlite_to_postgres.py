"""One-shot copy of a VMDR SQLite database into an empty PostgreSQL database.

Usage (from backend/):
    python scripts/sqlite_to_postgres.py ./data/vmdr.db postgresql+psycopg://user:pass@host:5432/vmdr

Behaviour:
- Creates the schema on PostgreSQL with SQLModel.metadata.create_all.
- Refuses to run if any target table already contains rows (safe by default).
- Copies tables in dependency order, keeping primary keys, in batches of 1000 rows.
- Runs in a single transaction: any failure rolls the whole copy back.
- Resets PostgreSQL id sequences so new inserts do not collide with copied ids.

Run the app once against the SQLite file first (init_db applies the additive SQLite
migrations), so the SQLite file has every column the models expect.
"""

import sys
from pathlib import Path

# Make `app` importable when run as `python scripts/sqlite_to_postgres.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import SQLModel, create_engine  # noqa: E402

from app import models  # noqa: E402,F401  (registers tables on SQLModel.metadata)

BATCH_SIZE = 1000


def _sqlite_engine(path: Path):
    return create_engine(f"sqlite:///{path}")


def _pg_engine(url: str):
    if not url.startswith("postgresql"):
        sys.exit(f"Destination must be a postgresql URL, got: {url.split('://', 1)[0]}://...")
    return create_engine(url, pool_pre_ping=True)


def _reset_sequences(conn, table: sa.Table) -> None:
    pk = list(table.primary_key.columns)
    if len(pk) != 1 or not isinstance(pk[0].type, sa.Integer):
        return
    col = pk[0].name
    conn.execute(sa.text(
        f"SELECT setval(pg_get_serial_sequence(:tbl, :col), "
        f"COALESCE(MAX({col}), 1), MAX({col}) IS NOT NULL) FROM {table.name}"
    ), {"tbl": table.name, "col": col})


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    sqlite_path = Path(argv[0]).expanduser().resolve()
    if not sqlite_path.is_file():
        print(f"SQLite file not found: {sqlite_path}")
        return 1

    src = _sqlite_engine(sqlite_path)
    dst = _pg_engine(argv[1])
    tables = SQLModel.metadata.sorted_tables  # parents before children

    SQLModel.metadata.create_all(dst)

    with dst.connect() as probe:
        for table in tables:
            n = probe.execute(sa.select(sa.func.count()).select_from(table)).scalar_one()
            if n:
                print(f"Refusing to run: PostgreSQL table '{table.name}' already has {n} rows. "
                      "Copy into an empty database.")
                return 1

    src_tables = set(sa.inspect(src).get_table_names())
    counts: dict[str, int] = {}

    with src.connect() as sconn, dst.begin() as dconn:
        for table in tables:
            if table.name not in src_tables:
                counts[table.name] = 0
                continue
            src_cols = {c["name"] for c in sa.inspect(src).get_columns(table.name)}
            cols = [table.c[c.name] for c in table.columns if c.name in src_cols]
            result = sconn.execute(sa.select(*cols))
            copied = 0
            while True:
                rows = [dict(r._mapping) for r in result.fetchmany(BATCH_SIZE)]
                if not rows:
                    break
                dconn.execute(table.insert(), rows)
                copied += len(rows)
            _reset_sequences(dconn, table)
            counts[table.name] = copied
            print(f"{table.name}: {copied} rows")

    print(f"Done. Copied {sum(counts.values())} rows across {len(counts)} tables.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
