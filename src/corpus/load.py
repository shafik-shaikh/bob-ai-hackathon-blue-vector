"""`python -m src.corpus.load` - ingest the four feeds into SQLite.

Runs the adapters over `src/corpus/feeds/`, loads the asset inventory, and
persists canonical alerts. Enrichment, correlation and scoring happen in
`src.pipeline.run`; this step is deliberately just ingestion so that the
canonical records can be inspected before anything is inferred from them.
"""

from __future__ import annotations

from src.config import settings
from src.db.store import connection, init_db, replace_assets, upsert_alerts
from src.ingest import ingest_feeds
from src.ingest.base import asset_inventory


def load_corpus(*, verbose: bool = True) -> dict[str, int]:
    init_db()
    per_source = ingest_feeds(settings.feeds_dir)
    counts = {}
    with connection() as conn:
        replace_assets(asset_inventory(), conn)
        for source, alerts in per_source.items():
            counts[source] = upsert_alerts(alerts, conn)
    if verbose:
        for source, n in counts.items():
            print(f"[corpus] {source:<7} {n:>4} alerts")
        total_ind = sum(len(a.indicators) for alerts in per_source.values() for a in alerts)
        print(f"[corpus] {sum(counts.values())} alerts, {total_ind} indicator references, {len(asset_inventory())} assets")
    return counts


if __name__ == "__main__":
    load_corpus()
