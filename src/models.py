"""Canonical data contracts for AEGIS.

This module is the interface between every component. It is frozen early in the
build: ingest adapters produce these shapes, enrichment annotates them,
correlation consumes them, and the API and MCP server serialise them.

Nothing here imports from any other AEGIS module. That is deliberate - it keeps
the contract free of circular dependencies so all four workstreams can build
against it in parallel.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SourceType(str, Enum):
    """The four wire formats AEGIS ingests."""

    SIEM = "siem"
    SYSLOG = "syslog"
    GEO = "geo"
    INTEL = "intel"


class IndicatorType(str, Enum):
    """Indicator-of-compromise categories extracted from alert content.

    Rarity weighting in correlation Signal 1 is computed per type as well as per
    value, because a shared hash and a shared internal IP are not comparable
    evidence even when both are equally rare in the corpus.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    USER = "user"
    HOSTNAME = "hostname"
    CVE = "cve"
    MAC = "mac"


class Tactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics, declared in kill-chain order.

    The declaration order matters: Signal 4 scores a tactic transition by the
    forward distance between two members of this enum, so reordering these
    changes correlation behaviour. See correlation/tactics.py.
    """

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

    @property
    def chain_position(self) -> int:
        """Zero-based index in kill-chain order."""
        return list(Tactic).index(self)

    @classmethod
    def from_attack(cls, shortname: str) -> "Tactic":
        """Map an ATT&CK kill_chain_phases shortname onto the enum.

        ATT&CK v19 split *Defense Evasion* into *Stealth* and *Defense
        Impairment*. Both occupy the same kill-chain position for correlation
        purposes, so they collapse onto DEFENSE_EVASION here.
        """
        aliases = {"stealth": "defense-evasion", "defense-impairment": "defense-evasion"}
        return cls(aliases.get(shortname, shortname))


class SignalType(str, Enum):
    """The four independent correlation signals."""

    SHARED_INDICATOR = "shared_indicator"
    TEMPORAL = "temporal"
    ASSET_ADJACENCY = "asset_adjacency"
    TACTIC_PROGRESSION = "tactic_progression"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# ---------------------------------------------------------------------------
# Core records
# ---------------------------------------------------------------------------


class Indicator(BaseModel):
    """A single observable extracted from an alert."""

    type: IndicatorType
    value: str
    context: str | None = Field(
        default=None,
        description="Surrounding text or field name the indicator came from, kept "
        "so the evidence trail can quote the original.",
    )

    @field_validator("value")
    @classmethod
    def _normalise(cls, v: str) -> str:
        # Case-folding matters: correlation matches indicators by exact value, and
        # the same hash arrives uppercase from one feed and lowercase from another.
        return v.strip().lower()

    def __hash__(self) -> int:
        return hash((self.type, self.value))


class AssetRef(BaseModel):
    """The system or principal an alert concerns.

    Criticality is not set by ingestion - it is joined from the asset inventory
    during scoring, because a feed has no way of knowing what a host is worth.
    """

    asset_id: str
    hostname: str | None = None
    ip: str | None = None
    subnet: str | None = None
    user_principal: str | None = None
    criticality: int | None = Field(
        default=None, ge=1, le=5, description="1 = negligible, 5 = mission critical."
    )


class TechniqueMapping(BaseModel):
    """One candidate ATT&CK technique for an alert.

    An alert carries several of these, ranked. Correlation Signal 4 reads only
    the top-ranked mapping; the full list is retained for the evidence trail and
    for the ATT&CK view in the console.
    """

    technique_id: str = Field(description="e.g. T1059.001")
    technique_name: str
    tactic: Tactic
    score: float = Field(ge=0.0, le=1.0, description="Calibrated confidence.")
    method: Literal["embedding", "keyword", "blended"] = "blended"


class Alert(BaseModel):
    """The canonical alert. Every ingest adapter produces exactly this shape.

    `raw_payload` is never dropped. Chain of evidence is the entire premise of
    the system: any claim AEGIS makes must be traceable back to the original
    record as the feed emitted it.
    """

    alert_id: str
    source: SourceType
    timestamp: datetime
    raw_text: str = Field(description="Human-readable alert content, used for ATT&CK mapping.")
    source_severity: str | None = Field(
        default=None,
        description="Vendor severity, preserved verbatim. Deliberately NOT normalised "
        "into our scoring - comparing incompatible vendor scales is the original problem.",
    )
    asset: AssetRef | None = None
    indicators: list[Indicator] = Field(default_factory=list)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_technique(self) -> TechniqueMapping | None:
        """Highest-scoring technique mapping, or None if unmapped."""
        return max(self.techniques, key=lambda t: t.score, default=None)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


class SignalContribution(BaseModel):
    """One signal's contribution to one edge.

    This is the atom of the evidence trail. `explain_correlation` in the MCP
    server renders a list of these into prose, so `rationale` is written for an
    analyst to read, not for a log.
    """

    signal: SignalType
    weight: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(
        description="Plain-language reason, e.g. 'Both alerts reference SHA-256 "
        "a3f1... which appears in only 2 of 487 alerts.'"
    )


class CorrelationEdge(BaseModel):
    """A weighted link between two alerts, with its evidence."""

    alert_a: str
    alert_b: str
    total_weight: float = Field(ge=0.0)
    contributions: list[SignalContribution]

    @property
    def fired_signals(self) -> list[SignalType]:
        return [c.signal for c in self.contributions if c.weight > 0]


class ScoreBreakdown(BaseModel):
    """The four prioritisation factors, kept separate on purpose.

    Collapsing these into one number is what makes existing tools unusable. The
    console renders this decomposition directly and `why_deprioritised` reads it.
    """

    correlation_confidence: float = Field(ge=0.0, le=1.0)
    asset_criticality: float = Field(ge=0.0, le=1.0)
    tactic_severity: float = Field(ge=0.0, le=1.0)
    false_positive_likelihood: float = Field(
        ge=0.0, le=1.0, description="Higher means more likely benign. Subtracts from the total."
    )
    suppression_rules_fired: list[str] = Field(
        default_factory=list, description="Named rules, so a deprioritisation can be defended."
    )
    composite: float = Field(ge=0.0, le=100.0)


class Incident(BaseModel):
    """A connected component of the alert graph above threshold."""

    incident_id: str
    alert_ids: list[str]
    edges: list[CorrelationEdge] = Field(default_factory=list)
    score: ScoreBreakdown | None = None
    first_seen: datetime
    last_seen: datetime

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)


class BlufReport(BaseModel):
    """A commander-ready brief.

    `gaps` is required rather than optional. An intelligence product that hides
    its own uncertainty is worse than no product, and the generator is not
    permitted to omit it.
    """

    incident_id: str
    bottom_line: str
    confidence: Confidence
    confidence_rationale: str
    assessment: str
    attack_chain: list[TechniqueMapping] = Field(
        description="Observed techniques in kill-chain order."
    )
    evidence: list[str] = Field(description="Alert IDs with source and timestamp.")
    recommended_actions: list[str]
    gaps: list[str] = Field(description="What is not known, and what would resolve it.")
    generated_by: Literal["watsonx", "template"] = "template"
