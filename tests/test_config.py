from pathlib import Path

import pytest
from pydantic import ValidationError

from evaly.config import ConfigError, load_settings

REPO_CONFIG = Path(__file__).parent.parent / "config.toml"

VALID_ENV = {
    "AGENT_BASE_URL": "http://localhost:11434/v1",
    "AGENT_API_KEY": "ollama",
    "AGENT_MODEL": "qwen3:8b",
    "JUDGE_BASE_URL": "https://judge.example/v1",
    "JUDGE_API_KEY": "sk-test-secret-123",
    "JUDGE_MODEL": "judge-model",
}

MINIMAL_TOML = """
[agent]
[judge]
[judge.limits]
rpm = 15
[cache]
dir = ".cache/responses"
"""


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


def test_repo_config_is_valid():
    settings = load_settings(REPO_CONFIG, env=VALID_ENV)
    assert settings.agent.model == "qwen3:8b"
    assert settings.judge.limits.rpd is not None


def test_merges_env_and_toml(tmp_path):
    settings = load_settings(write_config(tmp_path, MINIMAL_TOML), env=VALID_ENV)
    assert settings.judge.base_url == "https://judge.example/v1"
    assert settings.judge.api_key.get_secret_value() == "sk-test-secret-123"
    assert settings.judge.limits.rpm == 15
    assert settings.agent.limits.rpm is None  # no limit configured
    assert settings.cache.dir == Path(".cache/responses")


def test_missing_env_vars_are_all_listed(tmp_path):
    env = {k: v for k, v in VALID_ENV.items() if k not in ("JUDGE_API_KEY", "AGENT_MODEL")}
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, MINIMAL_TOML), env=env)
    assert "JUDGE_API_KEY" in str(exc.value)
    assert "AGENT_MODEL" in str(exc.value)


@pytest.mark.parametrize("value", ["", "   ", "replace-me"])
def test_empty_or_placeholder_env_counts_as_missing(tmp_path, value):
    env = {**VALID_ENV, "JUDGE_API_KEY": value}
    with pytest.raises(ConfigError, match="JUDGE_API_KEY"):
        load_settings(write_config(tmp_path, MINIMAL_TOML), env=env)


def test_secret_never_appears_in_repr_or_dump(tmp_path):
    settings = load_settings(write_config(tmp_path, MINIMAL_TOML), env=VALID_ENV)
    secret = VALID_ENV["JUDGE_API_KEY"]
    assert secret not in repr(settings)
    assert secret not in str(settings)
    assert secret not in settings.model_dump_json()


def test_model_name_in_toml_is_rejected(tmp_path):
    toml = MINIMAL_TOML.replace("[agent]", '[agent]\nmodel = "qwen3:8b"')
    with pytest.raises(ConfigError, match="AGENT_MODEL"):
        load_settings(write_config(tmp_path, toml), env=VALID_ENV)


def test_unknown_key_in_toml_is_rejected(tmp_path):
    toml = MINIMAL_TOML.replace("rpm = 15", "rmp = 15")  # typo
    with pytest.raises(ValidationError):
        load_settings(write_config(tmp_path, toml), env=VALID_ENV)


def test_invalid_value_is_rejected(tmp_path):
    toml = MINIMAL_TOML.replace("rpm = 15", "rpm = -1")
    with pytest.raises(ValidationError):
        load_settings(write_config(tmp_path, toml), env=VALID_ENV)


def test_missing_config_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "nope.toml", env=VALID_ENV)
