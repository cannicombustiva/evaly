"""Triage agent: a bounded tool-use loop ending with a validated `submit_triage` call.

Usage: uv run python -m evaly.agent examples/sample_case.json
"""

import json
import sys
import time
from pathlib import Path
from typing import Any

import openai
from pydantic import BaseModel, ConfigDict, ValidationError

from evaly.llm import ChatClient, ChatResponse, Message, Usage
from evaly.prompts import (
    AGENT_SYSTEM_PROMPTS,
    DEFAULT_PROMPT_VERSION,
    REPAIR_INVALID_SUBMIT,
    REPAIR_NO_TOOL_CALL,
)
from evaly.schemas import TriageInput, TriageOutput
from evaly.tools import SUBMIT_TOOL, ToolFixtures, execute_tool, tool_definitions
from evaly.trace import AgentRun, RunStatus, StepKind, TraceStep

DEFAULT_MAX_STEPS = 8
MAX_REPAIRS = 1  # one chance to fix a bad final answer; more just burns tokens


def render_input(inp: TriageInput) -> str:
    """Deterministic user message: same input, same text (matters for caching)."""
    return "Triage this alert.\n\n" + json.dumps(inp.model_dump(mode="json"), indent=2)


def run_agent(
    inp: TriageInput,
    fixtures: ToolFixtures,
    client: ChatClient,
    *,
    prompt_version: str = DEFAULT_PROMPT_VERSION,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> AgentRun:
    """Run one triage. Never raises on model or provider misbehavior: see `AgentRun.status`."""
    messages: list[Message] = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPTS[prompt_version]},
        {"role": "user", "content": render_input(inp)},
    ]
    tools = tool_definitions()
    run = AgentRun(status=RunStatus.MAX_STEPS, model="", prompt_version=prompt_version)
    start = time.perf_counter()

    def finish(status: RunStatus, **fields: Any) -> AgentRun:
        run.status = status
        run.latency_s = time.perf_counter() - start
        for key, value in fields.items():
            setattr(run, key, value)
        return run

    for _ in range(max_steps):
        try:
            resp = client.chat(messages, tools=tools)
        except openai.OpenAIError as exc:
            error = f"{type(exc).__name__}: {exc}"
            run.trace.append(TraceStep(kind=StepKind.ERROR, message=error))
            return finish(RunStatus.ERROR, error=error)

        _record_llm_call(run, resp)

        if not resp.tool_calls:
            if run.repairs >= MAX_REPAIRS:
                return finish(RunStatus.INVALID_OUTPUT, error="no submit_triage call")
            run.repairs += 1
            run.trace.append(TraceStep(kind=StepKind.REPAIR, message=REPAIR_NO_TOOL_CALL))
            messages.append({"role": "assistant", "content": resp.content or ""})
            messages.append({"role": "user", "content": REPAIR_NO_TOOL_CALL})
            continue

        messages.append(_assistant_message(resp))

        for call in resp.tool_calls:
            if call.name == SUBMIT_TOOL:
                output, error = _parse_submit(call.arguments)
                run.trace.append(
                    TraceStep(
                        kind=StepKind.SUBMIT,
                        tool_name=call.name,
                        arguments=call.arguments,
                        ok=output is not None,
                        message=error,
                    )
                )
                if output is not None:
                    return finish(RunStatus.OK, output=output)
                if run.repairs >= MAX_REPAIRS:
                    return finish(RunStatus.INVALID_OUTPUT, error=error)
                run.repairs += 1
                repair = REPAIR_INVALID_SUBMIT.format(error=error)
                run.trace.append(TraceStep(kind=StepKind.REPAIR, message=repair))
                # Every tool_call id must get a tool message, or the next request is invalid.
                messages.append({"role": "tool", "tool_call_id": call.id, "content": repair})
                continue

            ok, payload = execute_tool(fixtures, call.name, call.arguments)
            run.trace.append(
                TraceStep(
                    kind=StepKind.TOOL_CALL,
                    tool_name=call.name,
                    arguments=call.arguments,
                    ok=ok,
                    result=payload,
                )
            )
            messages.append(
                {"role": "tool", "tool_call_id": call.id, "content": json.dumps(payload)}
            )

    return finish(RunStatus.MAX_STEPS, error=f"no valid submit within {max_steps} steps")


def _record_llm_call(run: AgentRun, resp: ChatResponse) -> None:
    run.model = resp.model
    run.llm_calls += 1
    run.usage = Usage(
        prompt_tokens=run.usage.prompt_tokens + resp.usage.prompt_tokens,
        completion_tokens=run.usage.completion_tokens + resp.usage.completion_tokens,
    )
    run.trace.append(
        TraceStep(
            kind=StepKind.LLM_CALL,
            model=resp.model,
            content=resp.content,
            tool_calls=resp.tool_calls,
            usage=resp.usage,
            latency_s=resp.latency_s,
        )
    )


def _assistant_message(resp: ChatResponse) -> Message:
    return {
        "role": "assistant",
        "content": resp.content,
        "tool_calls": [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.name, "arguments": c.arguments},
            }
            for c in resp.tool_calls
        ],
    }


def _parse_submit(raw: str) -> tuple[TriageOutput | None, str | None]:
    try:
        return TriageOutput.model_validate_json(raw or "{}"), None
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'root'}: {e['msg']}" for e in exc.errors()
        )
        return None, errors


class Case(BaseModel):
    """Minimal case file for manual runs. The full dataset schema comes in Phase 2."""

    model_config = ConfigDict(extra="ignore")
    input: TriageInput
    fixtures: ToolFixtures


def main(argv: list[str]) -> int:
    from evaly.config import load_settings
    from evaly.llm import OpenAIChatClient

    if len(argv) != 1:
        print("usage: python -m evaly.agent <case.json>", file=sys.stderr)
        return 2
    case = Case.model_validate_json(Path(argv[0]).read_text())
    settings = load_settings()
    run = run_agent(case.input, case.fixtures, OpenAIChatClient(settings.agent))

    for step in run.trace:
        if step.kind == StepKind.TOOL_CALL:
            print(f"  tool  {step.tool_name}({step.arguments}) ok={step.ok}")
        elif step.kind in (StepKind.REPAIR, StepKind.ERROR):
            print(f"  {step.kind.value:<6}{step.message}")
    print(
        f"\nstatus={run.status.value} model={run.model} prompt={run.prompt_version} "
        f"llm_calls={run.llm_calls} repairs={run.repairs} "
        f"tokens={run.usage.total_tokens} latency={run.latency_s:.1f}s"
    )
    if run.output:
        print(run.output.model_dump_json(indent=2))
    if run.error:
        print(f"error: {run.error}")

    out_dir = Path("runs/manual")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{case.input.alert.id}.json"
    out_path.write_text(run.model_dump_json(indent=2))
    print(f"\ntrace saved to {out_path}")
    return 0 if run.status == RunStatus.OK else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
