# evaly

An evaluation suite for a small tool-using agent that triages synthetic security alerts.

The agent is only the system under test. The deliverable is the evaluation work:
dataset, deterministic checks, a validated LLM judge, a runner with baselines,
a CI gate in replay mode, and an experiments log driven by the numbers.

> Status: work in progress (Phase 1 — agent under test).

## Problem

TODO (Phase 8): why evaluating agents is hard, and what this suite measures.

## Architecture

TODO (Phase 8): diagram of agent, mocked tools, checks, judge, runner, reports.

## Results

TODO (Phase 6): results table and the rejected experiment.

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), [Ollama](https://ollama.com/) for the local agent model.

```bash
uv sync
cp .env.example .env    # fill in the judge API key and model id
ollama pull qwen3:8b
uv run pytest

# run the agent once on a synthetic example (trace saved under runs/manual/)
uv run python -m evaly.agent examples/sample_case.json
```

Configuration is split in two places:

| Where | What | Committed |
|---|---|---|
| `.env` | base URL, API key and model name for the agent and for the judge | no |
| `config.toml` | temperature, timeouts, retries, rate limits, daily token budget, cache dir | yes |

Any OpenAI-compatible endpoint works. Swapping providers means editing `.env` only.

## Zero-cost setup and its limits

- **Agent:** a small open model run locally with Ollama. No quota, but slow on a laptop.
- **Judge:** a larger hosted model on a free tier (currently Google AI Studio).
- Free tiers have per-minute and per-day caps that change often. They are read from
  `config.toml`, never hardcoded, and must be re-verified in the provider console.
- Free-tier providers may use inputs to improve their products. **All data in this repo
  is synthetic**: no real logs, IPs of real targets, malware or customer data.

TODO: document the measured impact of these limits (run time, sample sizes).

## Lessons learned

TODO (Phase 8).
