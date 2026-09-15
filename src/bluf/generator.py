"""BLUF orchestration: template first, watsonx refinement when available."""

from __future__ import annotations

from src.bluf.template import build_template_bluf, render_bluf_text
from src.bluf.watsonx_client import refine_with_watsonx
from src.models import Alert, BlufReport, Incident
from src.scoring.suppression import FiredRule


def generate_bluf(incident: Incident, alerts: list[Alert], fired: list[FiredRule], *, use_watsonx: bool = True) -> BlufReport:
    report = build_template_bluf(incident, alerts, fired)
    if use_watsonx:
        refined = refine_with_watsonx(report, incident.alert_ids)
        if refined is not None:
            return refined
    return report


__all__ = ["generate_bluf", "render_bluf_text"]
