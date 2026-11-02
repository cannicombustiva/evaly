import copy
import json
from pathlib import Path

import pytest

from evaly.dataset import (
    CASES_DIR,
    JSONL_PATH,
    Case,
    check_case,
    load_jsonl,
    to_jsonl,
    validate_dir,
)

REPO = Path(__file__).parent.parent
EXAMPLE = json.loads((REPO / CASES_DIR / "easy-port-scan-001.json").read_text())


def problems_for(mutate) -> list[str]:
    data = copy.deepcopy(EXAMPLE)
    mutate(data)
    return check_case(Case.model_validate(data))


def joined(problems: list[str]) -> str:
    return " | ".join(problems)


# --- the real dataset --------------------------------------------------------------------


def test_repo_dataset_is_valid():
    cases, problems = validate_dir(REPO / CASES_DIR)
    assert problems == {}, json.dumps(problems, indent=2)
    assert cases


def test_repo_jsonl_is_in_sync_with_case_files():
    cases, _ = validate_dir(REPO / CASES_DIR)
    jsonl = REPO / JSONL_PATH
    assert jsonl.exists(), "run: uv run python -m evaly.dataset build"
    assert jsonl.read_text() == to_jsonl(cases), "run: uv run python -m evaly.dataset build"


def test_jsonl_round_trip(tmp_path):
    cases, _ = validate_dir(REPO / CASES_DIR)
    path = tmp_path / "cases.jsonl"
    path.write_text(to_jsonl(cases))
    assert load_jsonl(path) == sorted(cases, key=lambda c: c.id)


# --- semantic rules ----------------------------------------------------------------------


def test_example_case_is_clean():
    assert problems_for(lambda d: None) == []


def test_id_prefix_must_match_category():
    assert "id must start with 'hard-'" in joined(problems_for(lambda d: d.update(category="hard")))


def test_severity_must_be_adjacent():
    def mutate(d):
        d["expected"].update(verdict="malicious", severity=["low", "critical"])

    assert "adjacent" in joined(problems_for(mutate))


def test_action_cannot_be_required_and_forbidden():
    def mutate(d):
        d["expected"]["required_actions"].append("block_ip")

    assert "both required and forbidden" in joined(problems_for(mutate))


def test_allowlist_always_forbidden():
    def mutate(d):
        d["expected"]["forbidden_actions"].remove("add_to_allowlist")

    assert "add_to_allowlist must be forbidden" in joined(problems_for(mutate))


def test_non_benign_must_forbid_close_alert_and_malicious_must_escalate():
    def mutate(d):
        d["expected"].update(verdict="malicious", severity=["high"], required_actions=[])

    found = joined(problems_for(mutate))
    assert "close_alert must be forbidden" in found
    assert "escalate_to_human must be required" in found


def test_benign_rules():
    def mutate(d):
        d["expected"].update(severity=["medium"], forbidden_actions=["add_to_allowlist"])

    found = joined(problems_for(mutate))
    assert "isolate_host must be forbidden" in found
    assert "disable_account must be forbidden" in found
    assert "benign cases must have severity ['low']" in found


def test_key_evidence_must_be_verbatim_in_data():
    def mutate(d):
        d["expected"]["key_evidence"] = ["CHG-9999"]

    assert "key_evidence not found" in joined(problems_for(mutate))


def test_key_evidence_matches_case_insensitively_and_in_dict_keys():
    def mutate(d):
        d["expected"]["key_evidence"] = ["chg-2211", "10.20.0.15"]

    assert problems_for(mutate) == []


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "151.101.1.69"])
def test_public_ips_are_rejected(ip):
    def mutate(d):
        d["input"]["logs"][0]["message"] += f" from {ip}"

    assert f"non-synthetic IP {ip}" in joined(problems_for(mutate))


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.1", "203.0.113.9", "198.51.100.4"])
def test_synthetic_ips_are_accepted(ip):
    def mutate(d):
        d["input"]["logs"][0]["message"] += f" from {ip}"

    assert problems_for(mutate) == []


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("http://payload.example/x.sh", True),
        ("https://login.example.com/reset", True),
        ("http://203.0.113.7/x.sh", True),
        ("http://evil-real-domain.com/x.sh", False),
        ("https://github.com/x", False),
    ],
)
def test_url_hosts_must_be_synthetic(url, ok):
    def mutate(d):
        d["input"]["logs"][0]["message"] += f" fetched {url}"

    found = joined(problems_for(mutate))
    assert ("non-synthetic URL host" not in found) is ok


def test_todo_placeholder_is_rejected():
    def mutate(d):
        d["label_notes"] = "TODO: explain"

    assert "TODO" in joined(problems_for(mutate))


# --- directory-level rules ----------------------------------------------------------------


def test_template_is_ignored_and_bad_files_are_reported(tmp_path):
    (tmp_path / "_template.json").write_text("{not json")
    (tmp_path / "easy-port-scan-001.json").write_text(json.dumps(EXAMPLE))
    (tmp_path / "wrong-name.json").write_text(json.dumps(EXAMPLE))  # duplicate id + bad name
    (tmp_path / "easy-broken-001.json").write_text('{"id": "easy-broken-001"}')

    cases, problems = validate_dir(tmp_path)

    assert [c.id for c in cases] == ["easy-port-scan-001"]
    assert "_template.json" not in problems
    assert "file name must be" in joined(problems["wrong-name.json"])
    assert "duplicate id" in joined(problems["wrong-name.json"])
    assert "category" in joined(problems["easy-broken-001.json"])  # schema errors listed
