"""Runtime configuration for AEGIS.

Every value the code reads from the environment is declared here, with the
same default that `src/.env.example` documents. Nothing else in the codebase
calls `os.environ` directly, so the .env.example file can be checked against
this module for completeness.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Load the repo-root .env if present. Existing environment variables win.
load_dotenv(REPO_ROOT / ".env", override=False)


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value.strip() == "" else value.strip()


def _env_float(name: str, default: float) -> float:
    return float(_env(name, str(default)))


def _env_int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


@dataclass(frozen=True)
class Settings:
    # Persistence
    database_path: Path
    # Corpus / reference data
    feeds_dir: Path
    ground_truth_path: Path
    asset_inventory_path: Path
    attack_corpus_path: Path
    # Enrichment
    embedding_backend: str  # "tfidf" (default, no heavy deps) or "sbert"
    embedding_model: str
    attack_mapping_floor: float
    attack_top_k: int
    # Correlation
    correlation_threshold: float
    temporal_halflife_seconds: float
    correlation_window_hours: float
    max_incident_size: int
    # BLUF generation
    watsonx_api_key: str
    watsonx_project_id: str
    watsonx_url: str
    watsonx_model_id: str
    bluf_top_n: int
    # API
    api_host: str
    api_port: int

    @property
    def watsonx_configured(self) -> bool:
        placeholder = ("", "your-api-key-here", "your-project-id-here")
        return self.watsonx_api_key not in placeholder and self.watsonx_project_id not in placeholder


def _database_path() -> Path:
    url = _env("DATABASE_URL", "sqlite:///aegis.db")
    if url.startswith("sqlite:///"):
        url = url[len("sqlite:///") :]
    path = Path(url)
    return path if path.is_absolute() else REPO_ROOT / path


def load_settings() -> Settings:
    return Settings(
        database_path=_database_path(),
        feeds_dir=SRC_DIR / "corpus" / "feeds",
        ground_truth_path=SRC_DIR / "corpus" / "ground_truth.json",
        asset_inventory_path=SRC_DIR / "corpus" / "asset_inventory.json",
        attack_corpus_path=SRC_DIR / "data" / "attack" / "enterprise_techniques.json",
        embedding_backend=_env("EMBEDDING_BACKEND", "tfidf").lower(),
        embedding_model=_env("EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
        attack_mapping_floor=_env_float("ATTACK_MAPPING_FLOOR", 0.35),
        attack_top_k=_env_int("ATTACK_TOP_K", 3),
        correlation_threshold=_env_float("CORRELATION_THRESHOLD", 0.45),
        temporal_halflife_seconds=_env_float("TEMPORAL_HALFLIFE_SECONDS", 3600),
        correlation_window_hours=_env_float("CORRELATION_WINDOW_HOURS", 24),
        max_incident_size=_env_int("MAX_INCIDENT_SIZE", 40),
        watsonx_api_key=_env("WATSONX_API_KEY", ""),
        watsonx_project_id=_env("WATSONX_PROJECT_ID", ""),
        watsonx_url=_env("WATSONX_URL", "https://eu-gb.ml.cloud.ibm.com"),
        watsonx_model_id=_env("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct"),
        bluf_top_n=_env_int("BLUF_TOP_N", 10),
        api_host=_env("API_HOST", "127.0.0.1"),
        api_port=_env_int("API_PORT", 8000),
    )


settings = load_settings()
