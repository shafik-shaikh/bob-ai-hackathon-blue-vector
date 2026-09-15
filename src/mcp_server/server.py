"""MCP server exposing AEGIS to IBM Bob.

    python -m src.mcp_server.server

Speaks MCP over stdio. Register it in Bob's MCP configuration (see
docs/setup-guide.md) and Bob gains six read-only tools that answer from the
persisted correlation state - the same SQLite the console reads.

Tools:
    get_priority_queue   "What should I look at first this shift?"
    explain_correlation  "Why are SIEM-0146 and SYS-0161 the same incident?"
    get_bluf             "Give me the BLUF for INC-014"
    why_deprioritised    "Why is critical alert SIEM-0121 ranked so low?"
    search_by_technique  "Show me everything mapped to T1059"
    get_incident         "Walk me through INC-017"

The server is deliberately read-only. Nothing here can mutate state or act on
an asset: acting automatically on a probabilistic assessment is not something
we would recommend in this domain, and a tool that cannot do harm is a tool an
analyst will let Bob call freely.
"""

from __future__ import annotations

import asyncio
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from src import services
from src.services import NotFound

server = Server("aegis")

TOOLS: list[Tool] = [
    Tool(
        name="get_priority_queue",
        description=(
            "Return the top of the AEGIS incident queue, ranked by consequence (correlation confidence, asset criticality, "
            "kill-chain depth, false-positive likelihood) rather than vendor severity. Use for 'what should I look at first?'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50, "description": "How many incidents to return."},
                "min_alerts": {"type": "integer", "default": 2, "minimum": 1, "description": "Hide incidents with fewer alerts than this (2 hides singletons)."},
                "include_suppressed": {"type": "boolean", "default": False, "description": "Include incidents a suppression rule fired on."},
            },
        },
    ),
    Tool(
        name="explain_correlation",
        description=(
            "Explain why two alerts were (or were not) grouped into the same incident: the evidence trail of every correlation "
            "signal that fired on the edge or path between them, with weights and plain-language rationale."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "alert_a": {"type": "string", "description": "Alert ID, e.g. SIEM-0146"},
                "alert_b": {"type": "string", "description": "Alert ID, e.g. SYS-0161"},
            },
            "required": ["alert_a", "alert_b"],
        },
    ),
    Tool(
        name="get_bluf",
        description="Return the commander-ready BLUF brief for an incident (bottom line, confidence, assessment, ATT&CK chain, evidence, recommended actions, gaps).",
        inputSchema={
            "type": "object",
            "properties": {"incident_id": {"type": "string", "description": "Incident ID, e.g. INC-014"}},
            "required": ["incident_id"],
        },
    ),
    Tool(
        name="why_deprioritised",
        description=(
            "Explain why an alert the vendor marked critical/high sits where it does in the AEGIS queue: which suppression rules fired, "
            "on what evidence, the four-factor score decomposition, and what evidence would change the ranking."
        ),
        inputSchema={
            "type": "object",
            "properties": {"alert_id": {"type": "string", "description": "Alert ID, e.g. SIEM-0121"}},
            "required": ["alert_id"],
        },
    ),
    Tool(
        name="search_by_technique",
        description="Find incidents and alerts mapped to a MITRE ATT&CK technique (sub-techniques included), or search techniques by name.",
        inputSchema={
            "type": "object",
            "properties": {"technique": {"type": "string", "description": "Technique ID (T1059, T1059.001) or a name fragment (powershell)."}},
            "required": ["technique"],
        },
    ),
    Tool(
        name="get_incident",
        description="Full detail for one incident: ranked position, score decomposition with explanations, kill chain, alert timeline and correlation edges.",
        inputSchema={
            "type": "object",
            "properties": {"incident_id": {"type": "string", "description": "Incident ID, e.g. INC-017"}},
            "required": ["incident_id"],
        },
    ),
]


# ---------------------------------------------------------------------------
# Renderers - Bob gets prose it can relay, plus the JSON for precision.
# ---------------------------------------------------------------------------


def _queue_text(rows: list[dict]) -> str:
    if not rows:
        return "The queue is empty. Run the pipeline first (python -m src.pipeline.run)."
    lines = ["AEGIS priority queue (ranked by consequence, not vendor severity):", ""]
    for r in rows:
        sev = ", ".join(f"{n} {s}" for s, n in sorted(r["vendor_severities"].items(), key=lambda kv: -kv[1]))
        top = r["top_technique"]
        lines.append(
            f"#{r['rank']} {r['incident_id']} score {r['score']['composite']:.0f}/100 — {r['title']}\n"
            f"    {r['alert_count']} alerts ({', '.join(f'{k}:{v}' for k, v in r['sources'].items())}); assets {', '.join(r['assets']) or 'n/a'}; "
            f"deepest tactic {r['tactics'][-1] if r['tactics'] else 'none'}; top technique {top['technique_id'] + ' ' + top['technique_name'] if top else 'none'}; "
            f"vendor severities {sev}\n"
            f"    why: {r['rationale']}"
        )
    return "\n".join(lines)


def _incident_text(d: dict) -> str:
    s = d["score"]
    lines = [
        f"{d['incident_id']} — rank {d['rank']} — score {s['composite']:.1f}/100",
        f"Title: {d['title']}",
        f"Window: {d['first_seen']} → {d['last_seen']}; {d['alert_count']} alerts from {', '.join(f'{k}:{v}' for k, v in d['sources'].items())}",
        f"Assets: {', '.join(d['assets']) or 'n/a'}",
        "Score decomposition:",
        f"  correlation confidence {s['correlation_confidence']:.2f} — {d['score_explanation']['correlation_confidence']}",
        f"  asset criticality      {s['asset_criticality']:.2f} — {d['score_explanation']['asset_criticality']}",
        f"  tactic severity        {s['tactic_severity']:.2f} — {d['score_explanation']['tactic_severity']}",
        f"  false-positive likelihood {s['false_positive_likelihood']:.2f} — {d['score_explanation']['false_positive_likelihood']}",
        f"  formula: {d['score_explanation']['formula']}",
        "Kill chain: " + (" → ".join(f"{t['technique_id']} {t['technique_name']} [{t['tactic']}]" for t in d["attack_chain"]) or "no technique mapped"),
        "Timeline:",
    ]
    for a in d["alerts"]:
        top = max(a["techniques"], key=lambda t: t["score"], default=None)
        lines.append(
            f"  {a['timestamp'][:16]}Z {a['alert_id']:10} [{a['source']}/{a['source_severity'] or 'n/a'}] "
            f"{(a['asset'] or {}).get('asset_id', '-'):14} {top['technique_id'] + ' ' if top else ''}{a['raw_text'][:90]}"
        )
    lines.append(f"Edges: {len(d['edges'])} (ask explain_correlation for any pair).")
    return "\n".join(lines)


def _why_text(d: dict) -> str:
    lines = [
        f"{d['alert_id']}: vendor severity '{d['vendor_severity']}' ({d['source']}) — AEGIS queue position {d['queue_position']} of {d['total_incidents']} "
        f"as part of {d['incident_id']} (score {d['score']['composite']:.1f}/100).",
        "",
        d["narrative"],
    ]
    if d["rules_fired"]:
        lines += ["", "Suppression rules fired:"]
        for r in d["rules_fired"]:
            lines.append(f"  • {r['rule_id']} ({r['name']}, strength {r['strength']:.2f})\n    rationale: {r['rationale']}\n    evidence: {r['evidence']}")
    return "\n".join(lines)


def _technique_text(term: str) -> str:
    term = term.strip()
    is_id = term.upper().startswith("T") and term[1:].replace(".", "").isdigit()
    if is_id:
        d = services.technique_detail(term)
        t = d["technique"]
        lines = [f"{t['technique_id']} {t['name']} [{', '.join(t['tactics'])}] — {len(d['alert_ids'])} alert(s), {len(d['incidents'])} incident(s).", ""]
        if d["incidents"]:
            lines.append(_queue_text(d["incidents"]))
        else:
            lines.append("No incident touches this technique.")
        lines.append("")
        lines.append(f"Alerts: {', '.join(d['alert_ids']) or 'none'}")
        return "\n".join(lines)
    rows = services.search_techniques(term, limit=15)
    if not rows:
        return f"No technique matches '{term}'."
    return "Matching techniques (alerts / incidents in the current corpus):\n" + "\n".join(
        f"  {r['technique_id']:10} {r['name']:45} [{', '.join(r['tactics'])}]  {r['alert_count']} alerts / {r['incident_count']} incidents" for r in rows
    )


def _explain_text(d: dict) -> str:
    return d["narrative"]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "get_priority_queue":
            limit = int(arguments.get("limit", 10))
            min_alerts = int(arguments.get("min_alerts", 2))
            include_suppressed = bool(arguments.get("include_suppressed", False))
            rows = services.get_queue(limit=limit * 3, min_alerts=min_alerts)
            if not include_suppressed:
                rows = [r for r in rows if not r["score"]["suppression_rules_fired"]]
            rows = rows[:limit]
            return [TextContent(type="text", text=_queue_text(rows)), TextContent(type="text", text=json.dumps(rows, indent=1))]
        if name == "explain_correlation":
            d = services.explain_correlation(arguments["alert_a"], arguments["alert_b"])
            return [TextContent(type="text", text=_explain_text(d)), TextContent(type="text", text=json.dumps(d, indent=1))]
        if name == "get_bluf":
            text = services.bluf_text(arguments["incident_id"])
            return [TextContent(type="text", text=text)]
        if name == "why_deprioritised":
            d = services.why_deprioritised(arguments["alert_id"])
            return [TextContent(type="text", text=_why_text(d)), TextContent(type="text", text=json.dumps(d, indent=1))]
        if name == "search_by_technique":
            return [TextContent(type="text", text=_technique_text(arguments["technique"]))]
        if name == "get_incident":
            d = services.get_incident_detail(arguments["incident_id"])
            return [TextContent(type="text", text=_incident_text(d))]
        return [TextContent(type="text", text=f"Unknown tool {name}")]
    except NotFound as exc:
        return [TextContent(type="text", text=f"Not found: {exc}")]
    except KeyError as exc:
        return [TextContent(type="text", text=f"Missing argument: {exc}")]


async def _main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
