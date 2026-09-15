"""Optional watsonx.ai (Granite) BLUF refinement.

The template brief is always generated first. When watsonx credentials are
configured and the `ibm-watsonx-ai` SDK is installed, the structured evidence
is sent to a Granite instruct model with a strict JSON schema and the model's
narrative fields replace the template's *only if* the response validates.
Any failure - missing SDK, network, timeout, malformed JSON, hallucinated
alert IDs - falls back to the template silently and marks `generated_by`.

The model is never allowed to invent evidence: `attack_chain` and `evidence`
are taken from the template regardless of what the model returns, and every
alert ID the model cites in narrative fields must exist in the incident.
"""

from __future__ import annotations

import json
import re

from src.config import settings
from src.models import BlufReport, Confidence

_PROMPT = """You are a defence SOC senior analyst writing a BLUF (Bottom Line Up Front) brief for a commander.
You are given a structured, machine-generated assessment of one incident. Rewrite the narrative fields so they
read as a crisp operational brief. Do NOT add facts that are not in the evidence. Do NOT change alert IDs,
technique IDs, asset names or timestamps. Keep the commander's questions in mind: what happened, how sure are
we, what do we do in the next 30 minutes, what do we not know.

Respond with ONLY a JSON object with these keys:
  "bottom_line": one sentence
  "assessment": two or three sentences
  "recommended_actions": list of 3 to 5 short imperative strings, most urgent first
  "gaps": list of 2 to 4 short strings

Structured assessment:
{evidence_json}
"""


def _sdk_available() -> bool:
    try:
        import ibm_watsonx_ai  # noqa: F401

        return True
    except Exception:
        return False


def refine_with_watsonx(report: BlufReport, alert_ids: list[str], *, timeout: float = 30.0) -> BlufReport | None:
    """Return a refined report, or None if watsonx is unavailable or its output is unusable."""
    if not settings.watsonx_configured or not _sdk_available():
        return None
    try:
        from ibm_watsonx_ai import Credentials
        from ibm_watsonx_ai.foundation_models import ModelInference

        creds = Credentials(url=settings.watsonx_url, api_key=settings.watsonx_api_key)
        model = ModelInference(
            model_id=settings.watsonx_model_id,
            credentials=creds,
            project_id=settings.watsonx_project_id,
            params={"decoding_method": "greedy", "max_new_tokens": 700, "repetition_penalty": 1.05},
        )
        payload = report.model_dump(mode="json")
        prompt = _PROMPT.format(evidence_json=json.dumps(payload, indent=1))
        text = model.generate_text(prompt=prompt)
    except Exception as exc:  # network, auth, quota - all of them fall back
        print(f"[bluf] watsonx unavailable ({exc.__class__.__name__}); using template")
        return None

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    def _clean_list(value, minimum: int) -> list[str] | None:
        if not isinstance(value, list) or len(value) < minimum:
            return None
        items = [str(v).strip() for v in value if str(v).strip()]
        return items if len(items) >= minimum else None

    bottom = str(data.get("bottom_line", "")).strip()
    assessment = str(data.get("assessment", "")).strip()
    actions = _clean_list(data.get("recommended_actions"), 2)
    gaps = _clean_list(data.get("gaps"), 1)
    if not (bottom and assessment and actions and gaps):
        return None

    # Guard against hallucinated alert IDs in the narrative.
    cited = set(re.findall(r"\b(?:SIEM|SYS|GEO|INTEL)-\d{3,4}\b", " ".join([bottom, assessment, *actions, *gaps])))
    if cited - set(alert_ids):
        print(f"[bluf] watsonx cited unknown alert IDs {sorted(cited - set(alert_ids))}; using template")
        return None

    return report.model_copy(
        update={
            "bottom_line": bottom,
            "assessment": assessment,
            "recommended_actions": actions,
            "gaps": gaps,
            "confidence": Confidence(report.confidence),
            "generated_by": "watsonx",
        }
    )
