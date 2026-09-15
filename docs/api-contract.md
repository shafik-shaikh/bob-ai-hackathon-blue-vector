# AEGIS REST API contract

The analyst console (`src/frontend/static/`) is built against this contract. The MCP server for IBM Bob
reads the same service layer (`src/services.py`), so the two surfaces never disagree.

Base URL: `http://localhost:8000`. All responses are JSON. Timestamps are ISO-8601 strings. The console
itself is served at `/` from the same process.

## Shared shapes

```jsonc
ScoreBreakdown {
  "correlation_confidence": 0.0-1.0,
  "asset_criticality": 0.0-1.0,
  "tactic_severity": 0.0-1.0,
  "false_positive_likelihood": 0.0-1.0,   // higher = more likely benign, subtracts
  "suppression_rules_fired": ["KNOWN_SCANNER_RANGE"],
  "composite": 0-100
}

TechniqueMapping { "technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution",
                   "score": 0.0-1.0, "method": "embedding|keyword|blended" }

Indicator { "type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email|user|hostname|cve", "value": "...", "context": "..." }

AssetRef { "asset_id": "FIN-WS-042", "hostname": "...", "ip": "...", "subnet": "...", "user_principal": "...",
           "criticality": 1-5 | null }

AlertView {
  "alert_id": "SIEM-0042", "source": "siem|syslog|geo|intel", "timestamp": "...",
  "raw_text": "...", "source_severity": "critical|high|... (vendor string, verbatim)",
  "asset": AssetRef | null, "indicators": [Indicator], "techniques": [TechniqueMapping],
  "raw_payload": { ...original record... },
  "incident_id": "INC-003" | null
}

SignalContribution { "signal": "shared_indicator|temporal|asset_adjacency|tactic_progression",
                     "weight": 0.0-1.0, "rationale": "plain-language reason" }

CorrelationEdge { "alert_a": "...", "alert_b": "...", "total_weight": 0.0-1.0+, "contributions": [SignalContribution] }

IncidentSummary {
  "incident_id": "INC-003", "rank": 1, "title": "Phishing → PowerShell → C2 on FIN-WS-042",
  "alert_count": 7, "sources": {"siem": 3, "syslog": 3, "intel": 1},
  "first_seen": "...", "last_seen": "...",
  "assets": ["FIN-WS-042", "DC01"],
  "tactics": ["initial-access", "execution", "command-and-control"],   // kill-chain order
  "top_technique": TechniqueMapping | null,
  "vendor_severities": {"critical": 1, "high": 2, "medium": 4},
  "score": ScoreBreakdown,
  "rationale": "one line: why it ranks where it does",
  "has_bluf": true
}

IncidentDetail = IncidentSummary + {
  "alerts": [AlertView],                       // timeline order
  "edges": [CorrelationEdge],
  "attack_chain": [ { "technique_id", "technique_name", "tactic", "score", "alert_ids": [] } ],  // kill-chain order
  "score_explanation": { "correlation_confidence": "...", "asset_criticality": "...", "tactic_severity": "...",
                         "false_positive_likelihood": "..." },
  "bluf": BlufReport | null
}

BlufReport {
  "incident_id": "...", "bottom_line": "...", "confidence": "High|Medium|Low", "confidence_rationale": "...",
  "assessment": "...", "attack_chain": [TechniqueMapping], "evidence": ["SIEM-0042 (siem, 2026-09-14T09:14Z): ..."],
  "recommended_actions": ["..."], "gaps": ["..."], "generated_by": "watsonx|template"
}

Disposition { "incident_id": "...", "verdict": "confirmed|false_positive", "note": "..."|null,
              "analyst": "..."|null, "updated_at": "..." }
```

`IncidentSummary` (and therefore `IncidentDetail`) also carries `"disposition": Disposition | null` — the
analyst's TP/FP verdict, when one has been recorded. It is a pure annotation: nothing in correlation or
scoring reads it back, so it cannot silently bias the ranking it is meant to audit.

## Endpoints

| Method & path | Returns | Notes |
|---|---|---|
| `GET /health` | `{"status":"ok","alerts":N,"incidents":N}` | |
| `GET /stats` | counts per stage, alerts by source, last pipeline run summary | landing-page header numbers |
| `GET /incidents?limit=50&min_alerts=1&tactic=&source=&q=` | `[IncidentSummary]` ranked | `min_alerts=2` hides singletons |
| `GET /incidents/{id}` | `IncidentDetail` | 404 if unknown |
| `GET /incidents/{id}/bluf` | `BlufReport` | generated on demand if missing |
| `GET /incidents/{id}/explain?a=ALERT&b=ALERT` | `{ "alert_a", "alert_b", "same_incident": bool, "edge": CorrelationEdge|null, "path": [CorrelationEdge], "narrative": "..." }` | direct edge, or shortest path when only transitively linked |
| `GET /alerts?limit=100&offset=0&source=&severity=&q=` | `{ "total": N, "items": [AlertView] }` | newest first |
| `GET /alerts/{id}` | `AlertView + { "incident_id", "queue_position", "total_incidents" }` | |
| `GET /alerts/{id}/why-deprioritised` | `{ "alert_id", "vendor_severity", "incident_id", "queue_position", "total_incidents", "score": ScoreBreakdown, "rules_fired": [{"rule_id","name","rationale","evidence"}], "narrative": "..." }` | the demo closer |
| `GET /techniques?q=powershell` | `[ { "technique_id", "name", "tactics": [], "incident_count", "alert_count" } ]` | search by id or name |
| `GET /techniques/{id}` | `{ technique, "incidents": [IncidentSummary], "alert_ids": [] }` | |
| `GET /assets` | `[ { "asset_id", "hostname", "ip", "subnet", "role", "criticality", "rationale" } ]` | |
| `PATCH /assets/{id}` | updated asset record | body `{"criticality": 1-5, "rationale"?}`; analyst override, applied by the *next* pipeline run (composite scores are computed once at pipeline time, not live — see docs/architecture.md) |
| `GET /feeds/raw?lines=40` | `{ "siem": "...", "syslog": "...", "geo": "...", "intel": "..." }` | raw feed excerpts for the "four unreadable feeds" view |
| `GET /suppression-rules` | `[ { "rule_id", "name", "rationale" } ]` | |
| `GET /dispositions` | `{ "INC-003": Disposition, ... }` | every recorded analyst verdict, keyed by incident id |
| `POST /incidents/{id}/disposition` | `Disposition` | body `{"verdict": "confirmed"\|"false_positive", "note"?, "analyst"?}` |
| `DELETE /incidents/{id}/disposition` | `{"ok": true}` | clears the verdict |

Errors are `{"detail": "..."}` with 404 / 422 status codes.
