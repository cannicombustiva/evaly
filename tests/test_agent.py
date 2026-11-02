"""Agent loop tests with a scripted fake client: fast, free, deterministic."""

import json
from typing import Any

import openai
import pytest

from evaly.agent import render_input, run_agent
from evaly.llm import ChatResponse, ToolCall, Usage
from evaly.schemas import TriageInput
from evaly.tools import ToolFixtures
from evaly.trace import RunStatus, StepKind

INPUT = TriageInput.model_validate(
    {
        "alert": {
            "id": "a-1",
            "timestamp": "2026-01-10T08:00:00Z",
            "title": "SSH brute force",
            "description": "48 failed logins then success",
            "host": "web-01",
            "source_ip": "203.0.113.7",
        },
        "logs": [
            {"timestamp": "2026-01-10T07:59:00Z", "source": "sshd", "message": "Failed pw (x48)"}
        ],
    }
)
FX = ToolFixtures.model_validate({"ips": {"203.0.113.7": {"reputation": "malicious"}}})

GOOD_SUBMIT = json.dumps(
    {
        "verdict": "malicious",
        "severity": "high",
        "rationale": "Malicious IP, brute force followed by success.",
        "recommended_actions": ["block_ip", "isolate_host"],
    }
)


def tool_resp(*calls: tuple[str, str], content: str | None = None) -> ChatResponse:
    return ChatResponse(
        model="fake",
        content=content,
        tool_calls=[
            ToolCall(id=f"call_{i}", name=n, arguments=a) for i, (n, a) in enumerate(calls)
        ],
        usage=Usage(prompt_tokens=100, completion_tokens=10),
        latency_s=0.01,
    )


def text_resp(content: str) -> ChatResponse:
    return ChatResponse(model="fake", content=content, usage=Usage(prompt_tokens=50))


class FakeClient:
    """Returns scripted responses in order; records every request it receives."""

    def __init__(self, script: list[ChatResponse | Exception]) -> None:
        self.script = list(script)
        self.requests: list[list[dict[str, Any]]] = []

    def chat(self, messages, tools=None) -> ChatResponse:
        self.requests.append([dict(m) for m in messages])
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_happy_path_investigates_then_submits():
    client = FakeClient(
        [
            tool_resp(("ip_reputation", '{"ip": "203.0.113.7"}')),
            tool_resp(("submit_triage", GOOD_SUBMIT)),
        ]
    )
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.OK
    assert run.output is not None and run.output.verdict == "malicious"
    assert run.tools_called == ["ip_reputation"]
    assert run.llm_calls == 2 and run.repairs == 0
    assert run.usage.prompt_tokens == 200 and run.usage.completion_tokens == 20
    assert [s.kind for s in run.trace] == [
        StepKind.LLM_CALL,
        StepKind.TOOL_CALL,
        StepKind.LLM_CALL,
        StepKind.SUBMIT,
    ]
    # The tool result was sent back with the matching tool_call_id.
    tool_msg = client.requests[1][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "call_0"
    assert json.loads(tool_msg["content"])["reputation"] == "malicious"


def test_invalid_submit_gets_one_repair():
    bad = json.dumps({"verdict": "evil", "severity": "high", "rationale": "x"})
    client = FakeClient(
        [tool_resp(("submit_triage", bad)), tool_resp(("submit_triage", GOOD_SUBMIT))]
    )
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.OK
    assert run.repairs == 1
    repair_msg = client.requests[1][-1]
    assert repair_msg["role"] == "tool" and "verdict" in repair_msg["content"]


def test_invalid_submit_twice_is_invalid_output():
    bad = '{"verdict": "evil"}'
    client = FakeClient([tool_resp(("submit_triage", bad)), tool_resp(("submit_triage", bad))])
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.INVALID_OUTPUT
    assert run.output is None and run.error


def test_malformed_submit_json_is_repaired():
    client = FakeClient(
        [tool_resp(("submit_triage", "{oops")), tool_resp(("submit_triage", GOOD_SUBMIT))]
    )
    assert run_agent(INPUT, FX, client).status is RunStatus.OK


def test_plain_text_answer_gets_one_nudge():
    client = FakeClient([text_resp("It is malicious."), tool_resp(("submit_triage", GOOD_SUBMIT))])
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.OK and run.repairs == 1
    assert client.requests[1][-1]["role"] == "user"


def test_plain_text_twice_is_invalid_output():
    client = FakeClient([text_resp("a"), text_resp("b")])
    assert run_agent(INPUT, FX, client).status is RunStatus.INVALID_OUTPUT


def test_repair_budget_is_shared():
    client = FakeClient([text_resp("a"), tool_resp(("submit_triage", '{"verdict": "evil"}'))])
    assert run_agent(INPUT, FX, client).status is RunStatus.INVALID_OUTPUT


def test_max_steps_stops_endless_investigation():
    loop = tool_resp(("ip_reputation", '{"ip": "203.0.113.7"}'))
    client = FakeClient([loop] * 3)
    run = run_agent(INPUT, FX, client, max_steps=3)

    assert run.status is RunStatus.MAX_STEPS
    assert run.llm_calls == 3


def test_unknown_tool_error_is_fed_back_and_run_continues():
    client = FakeClient(
        [tool_resp(("delete_logs", "{}")), tool_resp(("submit_triage", GOOD_SUBMIT))]
    )
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.OK
    failed = [s for s in run.trace if s.kind == StepKind.TOOL_CALL][0]
    assert failed.ok is False and "unknown tool" in failed.result["error"]


def test_parallel_tool_calls_all_get_answers():
    client = FakeClient(
        [
            tool_resp(
                ("ip_reputation", '{"ip": "203.0.113.7"}'),
                ("asset_info", '{"hostname": "web-01"}'),
            ),
            tool_resp(("submit_triage", GOOD_SUBMIT)),
        ]
    )
    run = run_agent(INPUT, FX, client)

    assert run.tools_called == ["ip_reputation", "asset_info"]
    ids = [m["tool_call_id"] for m in client.requests[1] if m["role"] == "tool"]
    assert ids == ["call_0", "call_1"]


def test_provider_error_becomes_error_status():
    client = FakeClient([openai.OpenAIError("connection refused")])
    run = run_agent(INPUT, FX, client)

    assert run.status is RunStatus.ERROR
    assert "connection refused" in (run.error or "")
    assert run.trace[-1].kind == StepKind.ERROR


def test_run_records_prompt_version_and_model():
    client = FakeClient([tool_resp(("submit_triage", GOOD_SUBMIT))])
    run = run_agent(INPUT, FX, client, prompt_version="v1")
    assert run.prompt_version == "v1" and run.model == "fake"


def test_unknown_prompt_version_fails_fast():
    with pytest.raises(KeyError):
        run_agent(INPUT, FX, FakeClient([]), prompt_version="v999")


def test_render_input_is_deterministic():
    assert render_input(INPUT) == render_input(
        TriageInput.model_validate_json(INPUT.model_dump_json())
    )


def test_run_serializes_to_json_and_back():
    client = FakeClient([tool_resp(("submit_triage", GOOD_SUBMIT))])
    run = run_agent(INPUT, FX, client)
    restored = type(run).model_validate_json(run.model_dump_json())
    assert restored == run
