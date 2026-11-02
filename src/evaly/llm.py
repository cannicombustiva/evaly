"""Thin chat client boundary.

The agent depends on the `ChatClient` protocol, not on the OpenAI SDK. This keeps the agent
testable with scripted fakes, and lets the runner wrap a client with cache, rate limiting and
budget checks later without touching agent code.
"""

import time
from typing import Any, Protocol

import openai
from pydantic import BaseModel

from evaly.config import ModelSettings

Message = dict[str, Any]


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: str  # raw JSON string as returned by the model; may be invalid JSON


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ChatResponse(BaseModel):
    """Provider-neutral view of one chat completion. Plain data, so it can be cached as JSON."""

    model: str
    content: str | None = None
    tool_calls: list[ToolCall] = []
    usage: Usage = Usage()
    latency_s: float = 0.0


class ChatClient(Protocol):
    def chat(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        """Send one chat request. Raises `openai.OpenAIError` subclasses on failure."""
        ...


class OpenAIChatClient:
    """ChatClient for any OpenAI-compatible endpoint (Ollama, Gemini compat, Groq, ...).

    Timeout and retries come from config. The SDK retries transient failures (connection
    errors, 408, 409, 429, 5xx) with exponential backoff and does not retry other 4xx errors.
    """

    def __init__(self, settings: ModelSettings) -> None:
        self._settings = settings
        self._client = openai.OpenAI(
            base_url=settings.base_url,
            api_key=settings.api_key.get_secret_value(),
            timeout=settings.timeout_s,
            max_retries=settings.max_retries,
        )

    def chat(
        self, messages: list[Message], tools: list[dict[str, Any]] | None = None
    ) -> ChatResponse:
        kwargs: dict[str, Any] = {
            "model": self._settings.model,
            "messages": messages,
            "temperature": self._settings.temperature,
        }
        if tools:
            kwargs["tools"] = tools
        if self._settings.reasoning_effort is not None:
            kwargs["reasoning_effort"] = self._settings.reasoning_effort

        start = time.perf_counter()
        resp = self._client.chat.completions.create(**kwargs)
        latency = time.perf_counter() - start

        msg = resp.choices[0].message
        return ChatResponse(
            model=resp.model,
            content=msg.content,
            tool_calls=[
                ToolCall(id=tc.id, name=tc.function.name, arguments=tc.function.arguments or "")
                for tc in (msg.tool_calls or [])
                if tc.type == "function"
            ],
            usage=Usage(
                prompt_tokens=resp.usage.prompt_tokens if resp.usage else 0,
                completion_tokens=resp.usage.completion_tokens if resp.usage else 0,
            ),
            latency_s=latency,
        )
