"""MITRE ATT&CK technique mapping.

Each alert's text is matched against the Enterprise technique corpus
(`src/data/attack/enterprise_techniques.json`, extracted from the official
STIX 2.1 bundle at a pinned version) and the top-k candidates are returned
with a calibrated confidence.

Two signals are blended, and the blend is the honest part:

* **Semantic similarity.** Alert text is embedded and compared to technique
  descriptions. The default backend is a TF-IDF vector space built in numpy -
  no model download, runs anywhere in under a second. Set
  `EMBEDDING_BACKEND=sbert` to use `sentence-transformers` (`all-MiniLM-L6-v2`)
  when it is installed; the interface is identical.
* **Keyword rules.** Short, telegraphic alert strings ("vssadmin delete
  shadows") carry a technique in two words and defeat pure similarity, which
  spreads probability across every description that mentions a shadow copy.
  A curated rule table pins those cases. Rules are ranked *with* the semantic
  score, not instead of it, so a keyword hit that the description also
  supports scores higher than one that does not.

Measured accuracy against the corpus ground truth is reported by
`python -m src.eval.evaluate` rather than asserted here.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from src.config import settings
from src.models import Alert, Tactic, TechniqueMapping

# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]  # ATT&CK shortnames, already normalised to the enum
    description: str
    is_subtechnique: bool
    url: str

    @property
    def primary_tactic(self) -> Tactic:
        """The tactic used for kill-chain reasoning.

        ATT&CK lists several tactics for some techniques (T1053 Scheduled Task
        is Execution, Persistence and Privilege Escalation). For correlation
        we want the stage at which the technique is usually *first observed*;
        the overrides below encode that, everything else takes ATT&CK's own
        first-listed tactic.
        """
        preferred = PREFERRED_TACTIC.get(self.technique_id) or PREFERRED_TACTIC.get(self.technique_id.split(".")[0])
        if preferred and preferred in self.tactics:
            return Tactic(preferred)
        return Tactic(self.tactics[0])


# technique (or parent) -> tactic shortname. Reviewed by the domain owner.
PREFERRED_TACTIC = {
    "T1133": "initial-access",       # external remote services: the way in before it is persistence
    "T1078": "initial-access",       # valid accounts
    "T1053": "persistence",          # scheduled task / cron: usually seen as a foothold
    "T1543": "persistence",          # create or modify system process
    "T1547": "persistence",          # boot or logon autostart
    "T1505": "persistence",          # server software component (web shell)
    "T1557": "credential-access",    # adversary-in-the-middle
    "T1548": "privilege-escalation", # abuse elevation control
}


@lru_cache(maxsize=1)
def load_techniques() -> list[Technique]:
    data = json.loads(settings.attack_corpus_path.read_text(encoding="utf-8"))
    out: list[Technique] = []
    for t in data["techniques"]:
        tactics = tuple(dict.fromkeys(Tactic.from_attack(s).value for s in t["tactics"]))
        if not tactics:
            continue
        out.append(
            Technique(
                technique_id=t["technique_id"],
                name=t["name"],
                tactics=tactics,
                description=t["description"],
                is_subtechnique=t["is_subtechnique"],
                url=t.get("url", ""),
            )
        )
    return out


@lru_cache(maxsize=1)
def technique_index() -> dict[str, Technique]:
    return {t.technique_id: t for t in load_techniques()}


@lru_cache(maxsize=1)
def attack_version() -> str:
    return json.loads(settings.attack_corpus_path.read_text(encoding="utf-8")).get("attack_version", "unknown")


# ---------------------------------------------------------------------------
# Keyword rules
# ---------------------------------------------------------------------------

# (pattern, technique_id, confidence). Confidence reflects how unambiguous the
# phrase is: "vssadmin delete shadows" is T1490 with near certainty; "failed
# logon" only implies T1110 when the volume is abnormal, so the rule demands it.
KEYWORD_RULES: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"macro-enabled|\.docm\b|macro heuristics|attachment.*\.(docm|xlsm)", re.I), "T1566.001", 0.85),
    (re.compile(r"phish|invoice-themed|lure", re.I), "T1566.001", 0.70),
    (re.compile(r"winword\.exe.*powershell|parentimage=.*winword|macro launches powershell", re.I), "T1204.002", 0.85),
    (re.compile(r"powershell(\.exe)?\s+-(nop|w hidden|enc|encodedcommand)|encoded command|download cradle|net\.webclient", re.I), "T1059.001", 0.92),
    (re.compile(r"\bpowershell\b", re.I), "T1059.001", 0.60),
    (re.compile(r"/bin/bash -c|curl .*\| ?sh\b|curl-to-shell", re.I), "T1059.004", 0.85),
    (re.compile(r"task registered|schtasks|scheduled task|taskscheduler", re.I), "T1053.005", 0.85),
    (re.compile(r"crontab|\bcron\b.*replace", re.I), "T1053.003", 0.85),
    (re.compile(r"a service was installed|eventid=7045|new service", re.I), "T1543.003", 0.85),
    (re.compile(r"lsass|processaccess.*lsass|credential dump|mimikatz", re.I), "T1003.001", 0.90),
    (re.compile(r"ntdsutil|ntds\.dit|ntds extraction", re.I), "T1003.003", 0.92),
    (re.compile(r"beacon|ja3|periodic outbound|c2 channel|command-and-control", re.I), "T1071.001", 0.80),
    (re.compile(r"non-standard port|:4444\b|long-lived session.*port", re.I), "T1571", 0.80),
    (re.compile(r"password spray|spraying|failed (vpn )?authentications? .* across \d+ distinct|failed operator logons", re.I), "T1110.003", 0.90),
    (re.compile(r"brute force|\d+ ssh connection attempts", re.I), "T1110.001", 0.75),
    (re.compile(r"vpn (logon|authentication) .*unfamiliar|no previous logons outside|remote access.*unusual", re.I), "T1133", 0.75),
    (re.compile(r"net group|domain admins|sam_group|group enumeration", re.I), "T1069.002", 0.85),
    (re.compile(r"netshareenumall|share enumeration|smb share discovery", re.I), "T1135", 0.88),
    (re.compile(r"read \d[\d,]* files|file reads by single account|bulk file access|files under \\\\", re.I), "T1039", 0.80),
    (re.compile(r"7z\.exe a |archive.*-p -mhe|encrypted archive|\.7z\b", re.I), "T1560.001", 0.85),
    (re.compile(r"mega\.nz|personal cloud storage|dropbox\.com.*(GB|upload)", re.I), "T1567.002", 0.85),
    (re.compile(r"large outbound transfer|GB transferred .* over|exfiltration over the c2", re.I), "T1041", 0.85),
    (re.compile(r"admin\$|psexec|psexesvc|logontype 3 .*domain controller|privileged network logon", re.I), "T1021.002", 0.85),
    (re.compile(r"vssadmin.* delete shadows|shadow copies deleted|bcdedit .*recoveryenabled no", re.I), "T1490", 0.95),
    (re.compile(r"vssadmin(\.exe)? list shadows", re.I), "T1490", 0.55),
    (re.compile(r"\.lockbit|rename operations .* extension|ransom note|restore-files\.txt|mass encryption", re.I), "T1486", 0.95),
    (re.compile(r"masquerading|svchost_\.exe|unsigned .* not the windows", re.I), "T1036.005", 0.85),
    (re.compile(r"nmap|syn scan|port scan|vulnerability (check|probe|scan)|nessus|openvas", re.I), "T1046", 0.85),
    (re.compile(r"setup-restore\.action|cve-\d{4}-\d+ .*(exploit|attempt)|exploit attempt|signature match for cve", re.I), "T1190", 0.90),
    (re.compile(r"web ?shell|\.jsp\b.*(web root|created)|x\.jsp", re.I), "T1505.003", 0.92),
    (re.compile(r"rogue ap|evil[- ]twin|deauthentication frames|adversary-in-the-middle", re.I), "T1557", 0.85),
    (re.compile(r"unknown device .*vlan|mac .* not in asset register|hardware addition", re.I), "T1200", 0.85),
    (re.compile(r"modbus|write multiple registers|holding registers changed|plc", re.I), "T1565.001", 0.80),
    (re.compile(r"removable media|usb mass storage", re.I), "T1091", 0.35),
    (re.compile(r"nxdomain", re.I), "T1071.004", 0.25),
    (re.compile(r"loiter|small uas|unregistered .*uas|rf emitter|reconnaissance", re.I), "T1595", 0.55),
    (re.compile(r"sinkhole|residual beaconing", re.I), "T1071.001", 0.30),
]


# ---------------------------------------------------------------------------
# Semantic backends
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{2,}")
_STOP = set(
    "the and for with from that this are was were have has been not but into onto over under via per "
    "may can will also such than then them they their there these those which while where when what who "
    "adversaries adversary may use used using uses using system systems attacker attackers malicious "
    "eventid image parentimage commandline user subject file files process processes windows host hosts".split()
)


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]


class TfidfBackend:
    """Sparse TF-IDF cosine similarity in plain numpy."""

    name = "tfidf"

    def __init__(self, techniques: list[Technique]):
        docs = [_tokens(f"{t.name} {t.name} {t.description}") for t in techniques]
        df: Counter[str] = Counter()
        for d in docs:
            df.update(set(d))
        n = len(docs)
        self.vocab = {term: i for i, term in enumerate(df)}
        self.idf = np.zeros(len(self.vocab))
        for term, i in self.vocab.items():
            self.idf[i] = math.log((1 + n) / (1 + df[term])) + 1.0
        self.matrix = np.zeros((n, len(self.vocab)), dtype=np.float32)
        for row, d in enumerate(docs):
            self.matrix[row] = self._vector(d)

    def _vector(self, tokens: list[str]) -> np.ndarray:
        v = np.zeros(len(self.vocab), dtype=np.float32)
        counts = Counter(t for t in tokens if t in self.vocab)
        for term, c in counts.items():
            v[self.vocab[term]] = (1 + math.log(c)) * self.idf[self.vocab[term]]
        norm = np.linalg.norm(v)
        return v / norm if norm else v

    def similarities(self, text: str) -> np.ndarray:
        return self.matrix @ self._vector(_tokens(text))


class SbertBackend:
    """sentence-transformers backend; optional, same interface."""

    name = "sbert"

    def __init__(self, techniques: list[Technique], model_name: str):
        from sentence_transformers import SentenceTransformer  # imported lazily on purpose

        self.model = SentenceTransformer(model_name)
        docs = [f"{t.name}: {t.description[:600]}" for t in techniques]
        self.matrix = self.model.encode(docs, normalize_embeddings=True, batch_size=64)

    def similarities(self, text: str) -> np.ndarray:
        v = self.model.encode([text[:1000]], normalize_embeddings=True)[0]
        return self.matrix @ v


@lru_cache(maxsize=1)
def backend():
    techniques = load_techniques()
    if settings.embedding_backend == "sbert":
        try:
            return SbertBackend(techniques, settings.embedding_model)
        except Exception as exc:  # pragma: no cover - depends on optional install
            print(f"[attack] sentence-transformers unavailable ({exc.__class__.__name__}); using TF-IDF backend")
    return TfidfBackend(techniques)


# Cosine at which we call the semantic signal "confident". TF-IDF cosines on
# short alert strings rarely exceed 0.4; sentence embeddings run higher.
_SEMANTIC_SATURATION = {"tfidf": 0.30, "sbert": 0.55}


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def map_alert(alert: Alert, *, top_k: int | None = None, floor: float | None = None) -> list[TechniqueMapping]:
    top_k = top_k or settings.attack_top_k
    floor = settings.attack_mapping_floor if floor is None else floor
    techniques = load_techniques()
    index = technique_index()
    be = backend()
    sims = be.similarities(alert.raw_text)
    saturation = _SEMANTIC_SATURATION[be.name]
    semantic = {t.technique_id: min(1.0, max(0.0, float(s)) / saturation) for t, s in zip(techniques, sims)}

    keyword: dict[str, float] = {}
    for pattern, tid, conf in KEYWORD_RULES:
        if tid in index and pattern.search(alert.raw_text):
            keyword[tid] = max(keyword.get(tid, 0.0), conf)

    candidates: dict[str, tuple[float, str]] = {}
    for tid, kw in keyword.items():
        sem = semantic.get(tid, 0.0)
        # Keyword sets the floor; semantic agreement lifts it toward 1.
        score = kw + (1.0 - kw) * 0.5 * sem
        candidates[tid] = (score, "blended" if sem > 0.15 else "keyword")
    # Semantic-only candidates are capped: similarity alone is weak evidence.
    for tid, sem in sorted(semantic.items(), key=lambda kv: kv[1], reverse=True)[:10]:
        if tid not in candidates and sem > 0:
            candidates[tid] = (min(0.65, sem * 0.65), "embedding")

    ranked = sorted(candidates.items(), key=lambda kv: kv[1][0], reverse=True)
    out: list[TechniqueMapping] = []
    for tid, (score, method) in ranked:
        if score < floor:
            continue
        t = index[tid]
        out.append(
            TechniqueMapping(
                technique_id=tid,
                technique_name=t.name,
                tactic=t.primary_tactic,
                score=round(min(1.0, score), 3),
                method=method,
            )
        )
        if len(out) >= top_k:
            break
    return out


def map_alerts(alerts: list[Alert]) -> int:
    """Annotate alerts in place. Returns the number of mappings written."""
    total = 0
    for alert in alerts:
        alert.techniques = map_alert(alert)
        total += len(alert.techniques)
    return total
