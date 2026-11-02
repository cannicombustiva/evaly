"""Run record for one agent execution: final status, output, and a step-by-step trace.

Failures are data, not exceptions: the runner needs to count them, and the trace is what
explains why a case failed.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from evaly.llm import ToolCall, Usage
from evaly.schemas import TriageOutput


class RunStatus(StrEnum):
    OK = "ok"
    INVALID_OUTPUT = "invalid_output"  # no valid submit_triage after the repair attempt
    MAX_STEPS = "max_steps"  # step limit reached without a submit
    ERROR = "error"  # provider/transport failure after SDK retries


class StepKind(StrEnum):
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    SUBMIT = "submit"
    REPAIR = "repair"  # we asked the model to fix its output
    ERROR = "error"


class TraceStep(BaseModel):
    kind: StepKind
    # llm_call
    model: str | None = None
    content: str | None = None
    tool_calls: list[ToolCall] = []
    usage: Usage | None = None
    latency_s: float | None = None
    # tool_call / submit
    tool_name: str | None = None
    arguments: str | None = None  # raw JSON string from the model
    ok: bool | None = None
    result: dict[str, Any] | None = None
    # repair / error
    message: str | None = None


class AgentRun(BaseModel):
    status: RunStatus
    output: TriageOutput | None = None
    model: str
    prompt_version: str
    llm_calls: int = 0
    repairs: int = 0
    usage: Usage = Usage()
    latency_s: float = 0.0
    error: str | None = None
    trace: list[TraceStep] = []

    @property
    def tools_called(self) -> list[str]:
        """Investigation tools called, in order. Input for trajectory checks."""
        return [s.tool_name for s in self.trace if s.kind == StepKind.TOOL_CALL and s.tool_name]
