"""Central configuration for blue-kakapo.

Loaded from environment variables (prefix ``BK_``) and an optional ``.env`` file. Every setting
has a safe default so the platform runs on localhost with **no configuration and no API key**
(offline mode). Nothing here phones home; no telemetry leaves the host unless explicitly configured.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProviderKind(StrEnum):
    """Which LLM provider adapter the gateway should use."""

    OFFLINE = "offline"  # deterministic, no network, no key — the default
    ANTHROPIC = "anthropic"
    OPENAI = "openai"  # any OpenAI-compatible endpoint (OpenAI, Azure, OpenRouter, vLLM, LM Studio)
    OLLAMA = "ollama"  # native Ollama runtime


class MemoryBackend(StrEnum):
    """Where opt-in case memory lives."""

    FOLDER = "folder"  # embedded, file-based, for the UI-linked local folder (default)
    PGVECTOR = "pgvector"  # Postgres + pgvector
    EXTERNAL = "external"  # Qdrant / external DB (later stage)


class StorageBackend(StrEnum):
    SQLITE = "sqlite"  # dev / localhost-light default
    POSTGRES = "postgres"  # production / docker compose


class Settings(BaseSettings):
    """Runtime settings. Override any field with ``BK_<FIELD>`` env vars."""

    model_config = SettingsConfigDict(
        env_prefix="BK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- identity / deployment ---
    deployment_name: str = "blue-kakapo"
    default_tenant: str = "default"
    data_dir: Path = Field(default=Path("./data"))

    # --- storage ---
    storage_backend: StorageBackend = StorageBackend.SQLITE
    database_url: str | None = (
        None  # e.g. postgresql+psycopg://user:pass@host/db ; None -> sqlite file
    )

    # --- LLM provider gateway ---
    provider: ProviderKind = ProviderKind.OFFLINE
    model: str = "offline-deterministic"
    embedding_model: str = "offline-embed"
    reranker_model: str = "offline-rerank"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    ollama_base_url: str = "http://localhost:11434"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048
    llm_timeout_seconds: float = 120.0

    # --- memory ---
    memory_enabled_default: bool = False  # opt-in per case
    memory_backend: MemoryBackend = MemoryBackend.FOLDER
    memory_folder: Path | None = None  # the UI-linked system folder
    memory_root: Path | None = Field(
        default=None,
        description=(
            "If set, folders linked via the API must live under this base dir (defense against "
            "pointing memory at arbitrary server paths in a shared deployment). Unset = localhost "
            "trust: any path the process can write."
        ),
    )

    # --- guardian / safety ---
    guardian_default_disposition: str = "ask"  # never fail-open
    max_concurrent_actions: int = 5  # blast-radius cap
    containment_default_ttl_seconds: int = 3600  # time-boxed containment

    # --- api ---
    api_host: str = "127.0.0.1"
    api_port: int = 8713  # "BK13" on a phone keypad; avoids common defaults
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    allow_insecure_bind: bool = Field(
        default=False,
        description="Permit binding a non-loopback host while auth is disabled (NOT recommended).",
    )

    # --- auth / rbac (enterprise) ---
    auth_enabled: bool = (
        False  # localhost default: open (implicit local-admin). Enable for deploys.
    )
    api_tokens: list[str] = Field(
        default_factory=list,
        description="Static tokens as 'token:tenant:role1|role2' (for services/CI).",
    )
    oidc_issuer: str | None = None
    oidc_jwks_url: str | None = None
    oidc_audience: str | None = None
    oidc_tenant_claim: str = "tenant"
    oidc_roles_claim: str = "roles"

    # --- secrets ---
    secret_backend: str = "env"  # env | file | openbao
    secret_file: Path | None = None
    secret_file_key: str | None = Field(
        default=None,
        description="Base64 AES-256 key for the 'file' backend; unset = plaintext JSON.",
    )
    openbao_addr: str | None = None
    openbao_token: str | None = None
    openbao_mount: str = "secret"

    # --- observability ---
    log_level: str = "INFO"
    log_json: bool = False  # human logs for dev; JSON for prod
    otel_enabled: bool = False
    otel_endpoint: str | None = None

    def resolved_database_url(self) -> str:
        """Return a concrete SQLAlchemy URL, defaulting to a local SQLite file."""
        if self.database_url:
            return self.database_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{(self.data_dir / 'blue_kakapo.sqlite3').resolve()}"


@lru_cache
def get_settings() -> Settings:
    """Cached singleton settings accessor."""
    return Settings()
