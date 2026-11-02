"""Golden dataset: case schema, semantic validation, and the JSONL build.

Source of truth: one JSON file per case in `dataset/cases/` (readable, clean diffs).
`dataset/cases.jsonl` is generated from them and is what the rest of the pipeline reads.

Usage:
  uv run python -m evaly.dataset check   # validate every case, report all problems
  uv run python -m evaly.dataset build   # check, then write dataset/cases.jsonl
  uv run python -m evaly.dataset stats   # coverage counts
"""

import ipaddress
import re
import sys
from collections import Counter
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evaly.schemas import Action, Severity, TriageInput, Verdict
from evaly.tools import ToolFixtures

CASES_DIR = Path("dataset/cases")
JSONL_PATH = Path("dataset/cases.jsonl")

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
ID_PREFIX = {"easy": "easy", "hard": "hard", "adversarial": "adv"}
SYNTHETIC_DOMAIN = re.compile(
    r"(\.example|\.test|\.invalid|\.localhost|(^|\.)example\.(com|net|org))$", re.IGNORECASE
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
TODO = re.compile(r"\bTODO\b", re.IGNORECASE)
URL_HOST = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:'\"]+)", re.IGNORECASE)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Category(StrEnum):
    EASY = "easy"
    HARD = "hard"
    ADVERSARIAL = "adversarial"


class Suite(StrEnum):
    CAPABILITY = "capability"
    REGRESSION = "regression"


class Scenario(StrEnum):
    """Keep in sync with the scenario catalog in docs/dataset/labeling-guidelines.md."""

    SSH_BRUTEFORCE = "ssh_bruteforce"
    PASSWORD_SPRAY = "password_spray"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    PHISHING_CLICK = "phishing_click"
    MALWARE_EXECUTION = "malware_execution"
    C2_BEACON = "c2_beacon"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PORT_SCAN = "port_scan"
    MAINTENANCE_ACTIVITY = "maintenance_activity"
    ACCOUNT_LOCKOUT = "account_lockout"


ToolName = Literal["ip_reputation", "asset_info", "query_logs"]


class Expected(_Strict):
    verdict: Verdict
    severity: list[Severity] = Field(min_length=1, max_length=2)
    required_actions: list[Action] = []
    forbidden_actions: list[Action] = []
    required_tools: list[ToolName] = []
    key_evidence: list[str] = Field(min_length=1)


class Case(_Strict):
    id: str = Field(pattern=r"^(easy|hard|adv)-[a-z0-9]+(-[a-z0-9]+)*-\d{3}$")
    category: Category
    suite: Suite
    scenario: Scenario
    dev_subset: bool = False
    description: str = Field(min_length=10)
    input: TriageInput
    fixtures: ToolFixtures
    expected: Expected
    label_notes: str = Field(min_length=10)


# --- Semantic checks ------------------------------------------------------------------------


def check_case(case: Case) -> list[str]:
    """Rules pydantic can't express. Returns every problem found, empty list if clean."""
    problems: list[str] = []
    exp = case.expected

    if not case.id.startswith(ID_PREFIX[case.category] + "-"):
        problems.append(f"id must start with '{ID_PREFIX[case.category]}-' for {case.category}")

    # Severity: no duplicates, adjacent levels only.
    levels = sorted(SEVERITY_ORDER.index(s) for s in exp.severity)
    if len(set(levels)) != len(levels):
        problems.append("severity has duplicates")
    elif len(levels) == 2 and levels[1] - levels[0] != 1:
        problems.append("severity values must be adjacent levels")

    overlap = set(exp.required_actions) & set(exp.forbidden_actions)
    if overlap:
        problems.append(f"actions both required and forbidden: {sorted(overlap)}")

    # Policy rules (guidelines section 4).
    if Action.ADD_TO_ALLOWLIST not in exp.forbidden_actions:
        problems.append("add_to_allowlist must be forbidden in every case")
    if exp.verdict != Verdict.BENIGN and Action.CLOSE_ALERT not in exp.forbidden_actions:
        problems.append(f"close_alert must be forbidden when verdict is {exp.verdict}")
    if exp.verdict == Verdict.MALICIOUS and Action.ESCALATE_TO_HUMAN not in exp.required_actions:
        problems.append("escalate_to_human must be required when verdict is malicious")
    if exp.verdict == Verdict.BENIGN:
        for action in (Action.ISOLATE_HOST, Action.DISABLE_ACCOUNT):
            if action not in exp.forbidden_actions:
                problems.append(f"{action} must be forbidden when verdict is benign")
        if exp.severity != [Severity.LOW]:
            problems.append("benign cases must have severity ['low']")

    # Evidence must be reachable: present verbatim somewhere in input or fixtures.
    haystack = "\n".join(_strings(case.input.model_dump(mode="json")))
    haystack += "\n" + "\n".join(_strings(case.fixtures.model_dump(mode="json")))
    for ev in exp.key_evidence:
        if ev.strip().lower() not in haystack.lower():
            problems.append(f"key_evidence not found verbatim in input/fixtures: {ev!r}")

    # Synthetic-data guards and leftovers, over the whole case.
    everything = list(_strings(case.model_dump(mode="json")))
    for text in everything:
        for raw_ip in IPV4.findall(text):
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue  # e.g. version strings like 999.1.2.3
            if not ip.is_private:  # covers RFC 1918, loopback and RFC 5737 documentation ranges
                problems.append(f"non-synthetic IP {raw_ip}: use RFC 5737 or private ranges")
        for host in URL_HOST.findall(text):
            if not _synthetic_host(host):
                problems.append(f"non-synthetic URL host {host!r}: use *.example / *.test")
    if any(TODO.search(text) for text in everything):
        problems.append("contains a TODO placeholder")

    return sorted(set(problems))


def _synthetic_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return bool(SYNTHETIC_DOMAIN.search(host))


def _strings(node: Any) -> Iterator[str]:
    """Every string in a JSON-like tree, including dict keys (IPs and hostnames live there)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


# --- Loading --------------------------------------------------------------------------------


def case_files(cases_dir: Path = CASES_DIR) -> list[Path]:
    """Case files, sorted. Files starting with '_' (templates) are ignored."""
    return sorted(p for p in cases_dir.glob("*.json") if not p.name.startswith("_"))


def validate_dir(cases_dir: Path = CASES_DIR) -> tuple[list[Case], dict[str, list[str]]]:
    """Load and check every case file. Returns (valid cases, problems by file name)."""
    cases: list[Case] = []
    problems: dict[str, list[str]] = {}
    seen: dict[str, str] = {}

    for path in case_files(cases_dir):
        try:
            case = Case.model_validate_json(path.read_text())
        except ValidationError as exc:
            problems[path.name] = [
                f"{'.'.join(map(str, e['loc'])) or 'root'}: {e['msg']}" for e in exc.errors()
            ]
            continue
        file_problems = check_case(case)
        if path.stem != case.id:
            file_problems.append(f"file name must be '{case.id}.json'")
        if case.id in seen:
            file_problems.append(f"duplicate id, also in {seen[case.id]}")
        seen[case.id] = path.name
        if file_problems:
            problems[path.name] = file_problems
        else:
            cases.append(case)
    return cases, problems


def to_jsonl(cases: list[Case]) -> str:
    return "".join(c.model_dump_json() + "\n" for c in sorted(cases, key=lambda c: c.id))


def load_jsonl(path: Path = JSONL_PATH) -> list[Case]:
    """What the runner uses. Assumes the file was produced by `build`."""
    return [Case.model_validate_json(line) for line in path.read_text().splitlines() if line]


# --- Stats ----------------------------------------------------------------------------------


def stats(cases: list[Case]) -> str:
    n = len(cases)
    if n == 0:
        return "no cases"
    lines = [f"total: {n}"]

    def block(title: str, counter: Counter[str]) -> None:
        lines.append(f"\n{title}")
        for key, count in sorted(counter.items()):
            lines.append(f"  {key:<24} {count:>3}  ({count / n:.0%})")

    block("category", Counter(c.category.value for c in cases))
    block("verdict", Counter(c.expected.verdict.value for c in cases))
    block("suite", Counter(c.suite.value for c in cases))
    block("scenario", Counter(c.scenario.value for c in cases))
    block("dev_subset", Counter(str(c.dev_subset) for c in cases))

    lines.append("\ncategory x verdict")
    grid = Counter((c.category.value, c.expected.verdict.value) for c in cases)
    verdicts = [v.value for v in Verdict]
    lines.append("  " + " " * 12 + "".join(f"{v:>12}" for v in verdicts))
    for cat in Category:
        lines.append(
            f"  {cat.value:<12}" + "".join(f"{grid[(cat.value, v)]:>12}" for v in verdicts)
        )
    return "\n".join(lines)


# --- CLI ------------------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "check"
    if command not in {"check", "build", "stats"}:
        print(__doc__, file=sys.stderr)
        return 2

    cases, problems = validate_dir()
    for name, items in sorted(problems.items()):
        print(f"\n{name}")
        for item in items:
            print(f"  - {item}")
    total = len(case_files())
    print(f"\n{len(cases)}/{total} cases valid")

    if command == "stats":
        print("\n" + stats(cases))
        return 0
    if problems:
        return 1

    expected_jsonl = to_jsonl(cases)
    if command == "build":
        JSONL_PATH.write_text(expected_jsonl)
        print(f"wrote {JSONL_PATH}")
        return 0
    in_sync = JSONL_PATH.exists() and JSONL_PATH.read_text() == expected_jsonl
    if not in_sync:
        print(f"{JSONL_PATH} is out of date: run `python -m evaly.dataset build`")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
