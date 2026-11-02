"""Mocked, deterministic investigation tools.

Each case carries its own `ToolFixtures` (the "world" the tools can see). Tools are pure
functions of (fixtures, arguments): no network, no clock, no randomness. Same input, same
output, which makes runs repeatable, cacheable and safe to replay.

Tool definitions sent to the model are generated from the pydantic argument models, so the
schema the model sees and the schema we validate against cannot drift apart.
"""

import json
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evaly.schemas import LogLine, Severity, TriageOutput

MAX_LOG_RESULTS = 50
SUBMIT_TOOL = "submit_triage"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- Fixture data (per case) ---------------------------------------------------------------


class IpReputation(_Strict):
    reputation: Literal["clean", "suspicious", "malicious", "unknown"]
    tags: list[str] = []
    country: str | None = None


class AssetInfo(_Strict):
    owner: str
    criticality: Severity
    environment: Literal["prod", "staging", "dev"]
    role: str | None = None


class ToolFixtures(_Strict):
    ips: dict[str, IpReputation] = {}
    assets: dict[str, AssetInfo] = {}
    logs: dict[str, list[LogLine]] = {}  # hostname -> searchable log store

    @field_validator("assets", "logs")
    @classmethod
    def _lowercase_hostnames(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Lookups are case-insensitive; normalize keys so "Web-01" in a dataset still matches.
        return {k.strip().lower(): v for k, v in value.items()}


# --- Tool arguments (what the model must send) ----------------------------------------------


class IpReputationArgs(_Strict):
    ip: str = Field(description="IPv4 or IPv6 address to look up.")


class AssetInfoArgs(_Strict):
    hostname: str = Field(description="Internal hostname, e.g. web-01.")


class QueryLogsArgs(_Strict):
    hostname: str = Field(description="Host whose logs to search.")
    query: str = Field(description="Case-insensitive substring. Empty string returns all lines.")


# --- Tool implementations -------------------------------------------------------------------


def ip_reputation(fx: ToolFixtures, args: IpReputationArgs) -> dict[str, Any]:
    rep = fx.ips.get(args.ip.strip(), IpReputation(reputation="unknown"))
    return {"ip": args.ip, **rep.model_dump()}


def asset_info(fx: ToolFixtures, args: AssetInfoArgs) -> dict[str, Any]:
    asset = fx.assets.get(args.hostname.strip().lower())
    if asset is None:
        return {"hostname": args.hostname, "error": "host not found in asset inventory"}
    return {"hostname": args.hostname, **asset.model_dump(mode="json")}


def query_logs(fx: ToolFixtures, args: QueryLogsArgs) -> dict[str, Any]:
    lines = fx.logs.get(args.hostname.strip().lower())
    if lines is None:
        return {"hostname": args.hostname, "error": "no logs for this host", "lines": []}
    needle = args.query.lower()
    matches = [line for line in lines if needle in line.message.lower()]
    return {
        "hostname": args.hostname,
        "total_matches": len(matches),
        "lines": [m.model_dump(mode="json") for m in matches[:MAX_LOG_RESULTS]],
    }


class _Tool:
    def __init__(
        self,
        name: str,
        description: str,
        args_model: type[BaseModel],
        fn: Callable[[ToolFixtures, Any], dict[str, Any]] | None,
    ) -> None:
        self.name = name
        self.description = description
        self.args_model = args_model
        self.fn = fn

    def definition(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": inline_refs(self.args_model.model_json_schema()),
            },
        }


TOOLS: dict[str, _Tool] = {
    t.name: t
    for t in [
        _Tool(
            "ip_reputation",
            "Look up the threat-intel reputation of an IP address.",
            IpReputationArgs,
            ip_reputation,
        ),
        _Tool(
            "asset_info",
            "Look up an internal host: owner, criticality, environment, role.",
            AssetInfoArgs,
            asset_info,
        ),
        _Tool(
            "query_logs",
            "Search the recent logs of a host for lines containing a substring.",
            QueryLogsArgs,
            query_logs,
        ),
        _Tool(
            SUBMIT_TOOL,
            "Submit the final triage decision. Call exactly once, after investigating.",
            TriageOutput,
            None,  # handled by the agent loop, not executed
        ),
    ]
}


def tool_definitions() -> list[dict[str, Any]]:
    return [t.definition() for t in TOOLS.values()]


def execute_tool(fx: ToolFixtures, name: str, raw_arguments: str) -> tuple[bool, dict[str, Any]]:
    """Run an investigation tool. Never raises on bad model input.

    Returns (ok, payload). On failure the payload is an error message meant to be sent back
    to the model, so it can correct itself.
    """
    tool = TOOLS.get(name)
    if tool is None or tool.fn is None:
        return False, {"error": f"unknown tool '{name}'"}
    try:
        data = json.loads(raw_arguments or "{}")
        args = tool.args_model.model_validate(data)
    except json.JSONDecodeError as exc:
        return False, {"error": f"arguments are not valid JSON: {exc.msg}"}
    except ValidationError as exc:
        return False, {"error": f"invalid arguments: {_short_errors(exc)}"}
    return True, tool.fn(fx, args)


def _short_errors(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, e['loc'])) or 'root'}: {e['msg']}" for e in exc.errors())


def inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Replace pydantic's `$ref`/`$defs` with inline definitions.

    Some OpenAI-compatible backends handle `$ref` poorly in tool parameters; a flat schema is
    the most portable form.
    """
    defs = schema.get("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].rsplit("/", 1)[-1]])
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)
