import json

import pytest

from evaly.tools import (
    SUBMIT_TOOL,
    AssetInfo,
    IpReputation,
    ToolFixtures,
    execute_tool,
    tool_definitions,
)

FX = ToolFixtures.model_validate(
    {
        "ips": {"203.0.113.7": {"reputation": "malicious", "tags": ["ssh-bruteforce"]}},
        "assets": {"web-01": {"owner": "platform", "criticality": "high", "environment": "prod"}},
        "logs": {
            "web-01": [
                {"timestamp": "2026-01-10T08:00:00Z", "source": "sshd", "message": "Failed pw"},
                {"timestamp": "2026-01-10T08:01:00Z", "source": "sshd", "message": "Accepted pw"},
            ]
        },
    }
)


def call(name: str, **args):
    return execute_tool(FX, name, json.dumps(args))


def test_ip_reputation_known_and_unknown():
    ok, out = call("ip_reputation", ip="203.0.113.7")
    assert ok and out["reputation"] == "malicious"
    ok, out = call("ip_reputation", ip="192.0.2.99")
    assert ok and out["reputation"] == "unknown"


def test_asset_info_known_unknown_and_case_insensitive():
    ok, out = call("asset_info", hostname="WEB-01")
    assert ok and out["criticality"] == "high"
    ok, out = call("asset_info", hostname="nope-99")
    assert ok and "error" in out


def test_query_logs_substring_case_insensitive():
    ok, out = call("query_logs", hostname="web-01", query="FAILED")
    assert ok and out["total_matches"] == 1
    assert out["lines"][0]["message"] == "Failed pw"
    ok, out = call("query_logs", hostname="web-01", query="")
    assert out["total_matches"] == 2


def test_tools_are_deterministic():
    assert call("query_logs", hostname="web-01", query="pw") == call(
        "query_logs", hostname="web-01", query="pw"
    )


@pytest.mark.parametrize(
    ("name", "raw", "fragment"),
    [
        ("drop_database", "{}", "unknown tool"),
        (SUBMIT_TOOL, "{}", "unknown tool"),  # not executable as an investigation tool
        ("ip_reputation", "{not json", "not valid JSON"),
        ("ip_reputation", "{}", "invalid arguments"),
        ("ip_reputation", '{"ip": "1.2.3.4", "extra": 1}', "invalid arguments"),
    ],
)
def test_bad_calls_return_errors_instead_of_raising(name, raw, fragment):
    ok, out = execute_tool(FX, name, raw)
    assert not ok
    assert fragment in out["error"]


def test_tool_definitions_are_flat_and_complete():
    defs = tool_definitions()
    names = [d["function"]["name"] for d in defs]
    assert names == ["ip_reputation", "asset_info", "query_logs", SUBMIT_TOOL]
    dumped = json.dumps(defs)
    assert "$ref" not in dumped and "$defs" not in dumped
    submit = defs[-1]["function"]["parameters"]
    assert submit["properties"]["verdict"]["enum"] == ["benign", "suspicious", "malicious"]
    assert "add_to_allowlist" in submit["properties"]["recommended_actions"]["items"]["enum"]


def test_fixture_models_reject_bad_values():
    with pytest.raises(ValueError):
        IpReputation.model_validate({"reputation": "evil"})
    with pytest.raises(ValueError):
        AssetInfo.model_validate({"owner": "x", "criticality": "huge", "environment": "prod"})


def test_fixture_hostnames_are_case_insensitive():
    fx = ToolFixtures.model_validate(
        {"assets": {"Web-02": {"owner": "x", "criticality": "low", "environment": "dev"}}}
    )
    ok, out = execute_tool(fx, "asset_info", '{"hostname": "web-02"}')
    assert ok and out["owner"] == "x"
