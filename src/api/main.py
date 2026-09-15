"""FastAPI surface for the analyst console.

    uvicorn src.api.main:app --port 8000

Serves the REST contract in `docs/api-contract.md` and the static console
from `src/frontend/static/` at `/`. Every endpoint is a thin wrapper over
`src/services.py`, which the MCP server shares.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src import services
from src.services import NotFound

STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend" / "static"

app = FastAPI(
    title="AEGIS API",
    description="Alert Enrichment, Grouping & Intelligence Scoring - REST surface for the analyst console.",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])


def _wrap(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/health")
def health():
    return services.health()


@app.get("/stats")
def stats():
    return services.get_stats()


@app.get("/incidents")
def incidents(
    limit: int = Query(50, ge=1, le=1000),
    min_alerts: int = Query(1, ge=1),
    tactic: str | None = None,
    source: str | None = None,
    q: str | None = None,
):
    return services.get_queue(limit=limit, min_alerts=min_alerts, tactic=tactic, source=source, q=q)


@app.get("/incidents/{incident_id}")
def incident(incident_id: str):
    return _wrap(services.get_incident_detail, incident_id)


@app.get("/incidents/{incident_id}/bluf")
def incident_bluf(incident_id: str):
    return _wrap(services.get_or_create_bluf, incident_id)


@app.get("/incidents/{incident_id}/explain")
def incident_explain(incident_id: str, a: str, b: str):
    result = _wrap(services.explain_correlation, a, b)
    return result


@app.get("/alerts")
def alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    severity: str | None = None,
    q: str | None = None,
):
    return services.list_alerts(limit=limit, offset=offset, source=source, severity=severity, q=q)


@app.get("/alerts/{alert_id}")
def alert(alert_id: str):
    return _wrap(services.get_alert_detail, alert_id)


@app.get("/alerts/{alert_id}/why-deprioritised")
def alert_why(alert_id: str):
    return _wrap(services.why_deprioritised, alert_id)


@app.get("/techniques")
def techniques(q: str | None = None, limit: int = Query(40, ge=1, le=200)):
    return services.search_techniques(q, limit=limit)


@app.get("/techniques/{technique_id}")
def technique(technique_id: str):
    return _wrap(services.technique_detail, technique_id)


@app.get("/assets")
def assets():
    return services.list_assets()


@app.get("/feeds/raw")
def feeds_raw(lines: int = Query(40, ge=1, le=500)):
    return services.raw_feeds(lines)


@app.get("/suppression-rules")
def suppression_rules():
    return services.suppression_rules()


# The console. Mounted last so API routes take precedence.
if STATIC_DIR.exists():

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/", StaticFiles(directory=STATIC_DIR), name="console")
