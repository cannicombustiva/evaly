import pytest
from pydantic import ValidationError

from evaly.schemas import Action, TriageInput, TriageOutput, Verdict

VALID_OUTPUT = {
    "verdict": "malicious",
    "severity": "high",
    "rationale": "  Log shows 48 failed logins then success.  ",
    "recommended_actions": ["block_ip", "isolate_host"],
}


def test_valid_output_parses_and_normalizes():
    out = TriageOutput.model_validate(VALID_OUTPUT)
    assert out.verdict is Verdict.MALICIOUS
    assert out.rationale == "Log shows 48 failed logins then success."
    assert out.recommended_actions == [Action.BLOCK_IP, Action.ISOLATE_HOST]


@pytest.mark.parametrize(
    "patch",
    [
        {"verdict": "probably_bad"},
        {"severity": "urgent"},
        {"rationale": "   "},
        {"recommended_actions": []},
        {"recommended_actions": ["nuke_from_orbit"]},
        {"confidence": 0.9},  # unknown field
    ],
)
def test_invalid_output_is_rejected(patch):
    with pytest.raises(ValidationError):
        TriageOutput.model_validate({**VALID_OUTPUT, **patch})


def test_duplicate_actions_are_removed_keeping_order():
    out = TriageOutput.model_validate(
        {**VALID_OUTPUT, "recommended_actions": ["monitor", "block_ip", "monitor"]}
    )
    assert out.recommended_actions == [Action.MONITOR, Action.BLOCK_IP]


def test_triage_input_parses_iso_timestamps():
    data = {
        "alert": {
            "id": "a-1",
            "timestamp": "2026-01-10T08:00:00Z",
            "title": "t",
            "description": "d",
            "host": "web-01",
        },
        "logs": [{"timestamp": "2026-01-10T07:59:00Z", "source": "sshd", "message": "m"}],
    }
    parsed = TriageInput.model_validate(data)
    assert parsed.alert.source_ip is None
    assert parsed.logs[0].timestamp.year == 2026
