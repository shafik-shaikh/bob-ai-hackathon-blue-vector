"""One-command demo: database, corpus, pipeline, evaluation, API + console.

    python scripts/demo.py            # full run, then serve on http://localhost:8000
    python scripts/demo.py --no-serve # just (re)build the state

No infrastructure to provision: SQLite file in the repo root, console served
by the API process. Ctrl+C stops the server.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.config import settings  # noqa: E402
from src.corpus.load import load_corpus  # noqa: E402
from src.db.store import init_db  # noqa: E402
from src.eval.evaluate import evaluate  # noqa: E402
from src.pipeline.run import run_pipeline  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the AEGIS demo state and serve the console.")
    parser.add_argument("--no-serve", action="store_true", help="Do not start the API/console after building.")
    parser.add_argument("--no-watsonx", action="store_true", help="Skip watsonx even if configured.")
    parser.add_argument("--port", type=int, default=settings.api_port)
    args = parser.parse_args()

    print("== 1/4 database")
    init_db(reset=True)
    print("== 2/4 corpus")
    load_corpus()
    print("== 3/4 pipeline")
    run_pipeline(use_watsonx=not args.no_watsonx)
    print("== 4/4 evaluation")
    evaluate()
    if args.no_serve:
        return
    import uvicorn

    print(f"\n== console: http://localhost:{args.port}   API docs: http://localhost:{args.port}/docs")
    uvicorn.run("src.api.main:app", host=settings.api_host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
