"""`python -m src.db.init [--reset]` - create the SQLite schema."""

from __future__ import annotations

import argparse

from src.db.store import init_db


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialise the AEGIS SQLite database.")
    parser.add_argument("--reset", action="store_true", help="Delete any existing database first.")
    args = parser.parse_args()
    path = init_db(reset=args.reset)
    print(f"[db] schema ready at {path}")


if __name__ == "__main__":
    main()
