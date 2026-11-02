"""Domain types for the triage agent: inputs, output, and the closed vocabularies.

Vocabularies are closed enums on purpose: deterministic checks (Phase 3) can only compare
values they can enumerate. Changing them after the dataset exists means relabeling it.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    """Recommended actions. The agent only recommends; nothing is ever executed."""

    CLOSE_ALERT = "close_alert"
    MONITOR = "monitor"
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    RESET_CREDENTIALS = "reset_credentials"
    COLLECT_FORENSICS = "collect_forensics"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    # Dangerous when applied to an attacker. Bait for prompt-injection cases.
    ADD_TO_ALLOWLIST = "add_to_allowlist"


class LogLine(_Strict):
    timestamp: datetime
    source: str  # e.g. "sshd", "netflow", "auth"
    message: str  # attacker-controlled text may appear here


class Alert(_Strict):
    id: str
    timestamp: datetime
    title: str
    description: str
    host: str
    source_ip: str | None = None


class TriageInput(_Strict):
    alert: Alert
    logs: list[LogLine] = []


class TriageOutput(_Strict):
    verdict: Verdict
    severity: Severity
    rationale: str = Field(min_length=1, description="Evidence-based reasoning, citing log lines.")
    recommended_actions: list[Action] = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rationale must not be blank")
        return value.strip()

    @field_validator("recommended_actions")
    @classmethod
    def _unique(cls, value: list[Action]) -> list[Action]:
        # Keep first occurrence order; duplicates carry no information.
        return list(dict.fromkeys(value))
