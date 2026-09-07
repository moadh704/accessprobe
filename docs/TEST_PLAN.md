# AccessProbe — Test Plan

| | |
|--|--|
| Version | 0.4.0 |
| Updated | 2026-08-05 |
| Results | [TEST_RESULTS.md](TEST_RESULTS.md) |

Steps to validate AccessProbe and keep results reproducible on `127.0.0.1`.

## Goals

- Catch real horizontal / cross-role access bugs
- Keep false positives low when ownership and privilege context are provided
- Stable CLI and useful reports
- Every claim in the results doc can be re-run locally

## Status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Unit tests | Done (48/48) |
| 2 | Local IDOR lab | Done |
| 3 | Accuracy analysis | Done |
| 4 | Juice Shop (local) | Done; DVWA / PortSwigger optional |
| 5 | Edge cases | Done for core cases |
| 6 | CLI / reports | Done |
| 7 | Ownership + privileged roles | Done in v0.4.0 |

See [TEST_RESULTS.md](TEST_RESULTS.md).

## Phase 1 — Unit tests

```bash
pip install -e ".[dev]"
pytest -q
```

Expect: `48 passed`.

## Phase 2 — Local IDOR lab

```bash
python labs/idor_lab/server.py 8765
```

| Cookie | user_id | Role |
|--------|---------|------|
| alice | 1 | user |
| bob | 2 | user |
| admin | 3 | admin |

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05

accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"
```

Ground truth:

```bash
curl -s -H "Cookie: session=alice" "http://127.0.0.1:8765/vuln/profile?user_id=2"
curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: session=alice" \
  "http://127.0.0.1:8765/secure/profile?user_id=2"
```

Expect high-confidence findings on broken endpoints; secure foreign IDs quiet; with default v0.4 config, secure scan reports 0 vulnerable findings.

## Phase 3 — Accuracy

Classify notable findings as TP / FP / TN / FN. Focus on horizontal IDOR, self-access, intended admin, and junk candidates. Write up in `TEST_RESULTS.md`.

## Phase 4 — Other labs

| Lab | Priority | Notes |
|-----|----------|--------|
| Juice Shop (local) | High | Done — basket path IDOR |
| DVWA | High | Optional |
| PortSwigger Academy | High | Optional |
| bWAPP | Medium | Optional |

Per lab: config under `labs/<name>/`, two users, curl ground truth, scan with reports, classify findings, update results. Do not commit secrets.

```bash
# Juice Shop already on 127.0.0.1:3000
python labs/juice_shop/setup_and_scan.py
```

## Phase 5 — Edge cases

- [x] Numeric IDs
- [ ] UUIDs (patterns only so far)
- [x] Sequential IDs
- [x] Path parameters (`/resource/{id}`)
- [ ] JSON body (supported in code; needs a lab case)
- [x] Missing / invalid sessions
- [x] 401 / 403 / 404
- [ ] Redirects, large responses, 429
- [x] Bad / missing config
- [x] Noisy candidates

Expect: no crashes, clear errors, path URLs use `{name}`.

## Phase 6 — CLI and reports

- [x] Help text
- [x] Useful errors
- [x] JSON / HTML reports
- [x] Confidence shown
- [x] `cookie_file`, JWT headers, multi-param config

## Phase 7 — Backlog

- [x] Ownership map (`--own-ids`)
- [x] Privileged roles (`--privileged-roles`)
- [x] Candidate filtering (field names / dates)
- [x] `--min-confidence`
- [ ] Horizontal-only refinements
- [ ] JWT helpers beyond raw headers
- [ ] CSRF handling
- [x] Non-zero exit when high-confidence findings exist

## Documenting a run

Update `TEST_RESULTS.md` with: date/version, target, commands, ground truth, TP/FP tables, limitations, artifact paths.

## Order of work

1. `pytest -q`
2. Local lab suite
3. Juice Shop or other authorized local app
4. Document accuracy
5. Fix high-impact FPs if needed
6. Expand edge cases

## Authorization

Only test systems you own or have permission to test. Keep lab traffic on `127.0.0.1` unless you have written scope.

## Quick commands

```bash
pytest -q

python labs/idor_lab/server.py 8765
accessprobe scan --config labs/idor_lab/scan_vuln.yaml --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml --report labs/results/secure.json
accessprobe scan --config labs/idor_lab/scan_orders.yaml --report labs/results/orders.json
accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"

python labs/juice_shop/setup_and_scan.py
```
