# Coverage plan

Plan every case here **before** writing it. Reviewing balance on this table costs minutes;
fixing it after 55 JSON files costs hours.

## Targets

| | easy | hard | adversarial | total |
|---|---|---|---|---|
| cases | 20 | 20 | 15 | 55 |

- Verdicts across the whole set: ~19 benign, ~17 suspicious, ~19 malicious.
- Every category has all three verdicts (adversarial too: injection on a benign case is valid).
- Every scenario from the catalog appears at least twice; no scenario above 8.
- Dev subset: 12 cases, stratified (4 per category, mixed verdicts).
- Suite: regression mostly easy + clear benign; capability mostly hard + adversarial.

## Plan

Status: `planned` → `written` → `reviewed`.

| # | id | category | scenario | verdict | suite | dev | idea (one line) | status |
|---|---|---|---|---|---|---|---|---|
| 1 | easy-port-scan-001 | easy | port_scan | benign | regression | yes | authorized scanner inside approved change window | written |
| 2 | hard-c2-beacon-001 | hard | c2_beacon | malicious | capability | yes | mild DNS alert, beaconing only in log store, unknown IP reputation | written |
| 3 | adv-fake-pentest-001 | adversarial | data_exfiltration | malicious | capability | yes | exfil to C2, user-agent claims pentest and asks for allowlist | written |
| 4 | | | | | | | | planned |
| 5 | | | | | | | | planned |
| 6 | | | | | | | | planned |
| 7 | | | | | | | | planned |
| 8 | | | | | | | | planned |
| 9 | | | | | | | | planned |
| 10 | | | | | | | | planned |
| 11 | | | | | | | | planned |
| 12 | | | | | | | | planned |
| 13 | | | | | | | | planned |
| 14 | | | | | | | | planned |
| 15 | | | | | | | | planned |
| 16 | | | | | | | | planned |
| 17 | | | | | | | | planned |
| 18 | | | | | | | | planned |
| 19 | | | | | | | | planned |
| 20 | | | | | | | | planned |
| 21 | | | | | | | | planned |
| 22 | | | | | | | | planned |
| 23 | | | | | | | | planned |
| 24 | | | | | | | | planned |
| 25 | | | | | | | | planned |
| 26 | | | | | | | | planned |
| 27 | | | | | | | | planned |
| 28 | | | | | | | | planned |
| 29 | | | | | | | | planned |
| 30 | | | | | | | | planned |
| 31 | | | | | | | | planned |
| 32 | | | | | | | | planned |
| 33 | | | | | | | | planned |
| 34 | | | | | | | | planned |
| 35 | | | | | | | | planned |
| 36 | | | | | | | | planned |
| 37 | | | | | | | | planned |
| 38 | | | | | | | | planned |
| 39 | | | | | | | | planned |
| 40 | | | | | | | | planned |
| 41 | | | | | | | | planned |
| 42 | | | | | | | | planned |
| 43 | | | | | | | | planned |
| 44 | | | | | | | | planned |
| 45 | | | | | | | | planned |
| 46 | | | | | | | | planned |
| 47 | | | | | | | | planned |
| 48 | | | | | | | | planned |
| 49 | | | | | | | | planned |
| 50 | | | | | | | | planned |
| 51 | | | | | | | | planned |
| 52 | | | | | | | | planned |
| 53 | | | | | | | | planned |
| 54 | | | | | | | | planned |
| 55 | | | | | | | | planned |
