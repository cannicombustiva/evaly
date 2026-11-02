"""Typed settings: non-secret values from config.toml, endpoint and secrets from env vars."""

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, PositiveFloat, PositiveInt, SecretStr

ROLES = ("agent", "judge")
# Settings field -> env var suffix. Env var name is f"{ROLE}_{SUFFIX}", e.g. AGENT_MODEL.
ENV_FIELDS = {"base_url": "BASE_URL", "api_key": "API_KEY", "model": "MODEL"}
PLACEHOLDER = "replace-me"


class ConfigError(Exception):
    """Raised when settings are missing or invalid. Message says how to fix it."""


class _Strict(BaseModel):
    # Reject unknown keys so a typo in config.toml fails loudly instead of being ignored.
    model_config = ConfigDict(extra="forbid", frozen=True)


class Limits(_Strict):
    """Provider rate limits. None means no limit is enforced on our side."""

    rpm: PositiveInt | None = None
    tpm: PositiveInt | None = None
    rpd: PositiveInt | None = None


class ModelSettings(_Strict):
    """Everything needed to call one model in one role (agent or judge)."""

    base_url: str
    api_key: SecretStr
    model: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    timeout_s: PositiveFloat = 60.0
    max_retries: int = Field(default=3, ge=0)
    daily_token_budget: PositiveInt | None = None
    limits: Limits = Limits()


class CacheSettings(_Strict):
    dir: Path


class Settings(_Strict):
    agent: ModelSettings
    judge: ModelSettings
    cache: CacheSettings


def load_settings(
    config_path: Path = Path("config.toml"),
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Load settings. Pass `env` in tests; otherwise .env is loaded into os.environ."""
    if env is None:
        load_dotenv(override=False)  # real env vars win over .env
        env = os.environ

    try:
        raw = tomllib.loads(config_path.read_text())
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc

    missing: list[str] = []
    for role in ROLES:
        section = raw.setdefault(role, {})
        for field, suffix in ENV_FIELDS.items():
            var = f"{role.upper()}_{suffix}"
            if field in section:
                raise ConfigError(
                    f"'{role}.{field}' must come from env var {var}, not from {config_path}"
                )
            value = env.get(var, "").strip()
            if not value or value == PLACEHOLDER:
                missing.append(var)
            section[field] = value

    if missing:
        raise ConfigError(
            f"Missing env vars: {', '.join(missing)}. Copy .env.example to .env and fill them in."
        )

    return Settings.model_validate(raw)
