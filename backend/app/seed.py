"""Idempotent seeder: `python -m app.seed`. Safe to re-run; existing URLs are skipped."""

import json

from sqlmodel import Session

from app.db import engine, init_db
from app.seed_data import SEED_TARGETS
from app.services.targets import add_targets


def seed() -> dict:
    init_db()
    with Session(engine) as session:
        result = add_targets(session, urls=SEED_TARGETS, tags=["seed"])
    return {
        "created": len(result.created),
        "skipped_duplicates": len(result.skipped_duplicates),
        "invalid": [e.model_dump() for e in result.invalid],
    }


if __name__ == "__main__":
    print(json.dumps(seed(), indent=2))
