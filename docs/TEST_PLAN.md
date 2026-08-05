# AccessProbe — Testing Plan

| Field | Value |
|-------|--------|
| **Version** | 0.4.0 |
| **Last updated** | 2026-08-05 |
| **Companion report** | [`docs/TEST_RESULTS.md`](TEST_RESULTS.md) |
| **Audience** | Maintainers, AI agents, portfolio reviewers |

This plan is written so a human or AI assistant can execute it step-by-step and produce consistent, reproducible results suitable for public documentation.

---

## 1. Goals

| Goal | Description |
|------|-------------|
| Accuracy | Maximize true positives; minimize false positives on correct ACLs |
| Reliability | Stable CLI, no crashes, clear errors |
| Coverage | Common IDOR patterns: query, path, multi-role, horizontal |
| Usability | Readable reports, simple YAML, cookie + header auth |
| Reproducibility | Every claim can be re-run on `127.0.0.1` |
| Portfolio quality | Honest limitations, ground truth, artifact paths |

---

## 2. Phase status

| Phase | Name | Priority | Status |
|-------|------|----------|--------|
| 1 | Unit tests | Critical | **Done** (33/33) |
| 2 | Local IDOR lab | Critical | **Done** |
| 3 | Accuracy analysis | Critical | **Done** |
| 4 | Real vulnerable labs | High | **Done** (Juice Shop local); DVWA / PortSwigger / bWAPP optional next |
| 5 | Edge cases & robustness | High | **Done** (core cases); expand UUIDs / 429 later |
| 6 | Usability & reporting | Medium | **Done** |
| 7 | Advanced features | Medium | **Partial** — ownership map + privileged roles shipped in **v0.4.0** |

Detailed outcomes → **[TEST_RESULTS.md](TEST_RESULTS.md)**.

---

## 3. Phase 1 — Unit tests

```bash
pip install -e ".[dev]"
pytest -q
pytest -v --tb=short
```

**Success criteria**

- All tests pass
- Core modules covered: models, session, config, detector, tester, discovery, reporter, cli

**Expected:** `33 passed`

---

## 4. Phase 2 — Local IDOR laboratory

### Location

```text
labs/idor_lab/
```

### Start

```bash
python labs/idor_lab/server.py 8765
```

### Sessions

| Cookie value | user_id | Role |
|--------------|---------|------|
| alice | 1 | user |
| bob | 2 | user |
| admin | 3 | admin |

### Required scans

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05

accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"
```

### Manual verification

```bash
curl -s -H "Cookie: session=alice" "http://127.0.0.1:8765/vuln/profile?user_id=2"
curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: session=alice" \
  "http://127.0.0.1:8765/secure/profile?user_id=2"
```

### Success criteria

| Scenario | Expected |
|----------|----------|
| Horizontal IDOR (vuln) | High-confidence true positives |
| Secure horizontal | No FP on foreign user IDs for non-admins |
| Orders | Horizontal mutations flagged |
| Discovery | Finds `user_id`, `order_id`, etc. |

---

## 5. Phase 3 — Accuracy analysis

Classify every notable finding:

| Code | Meaning |
|------|---------|
| **TP** | Real IDOR correctly detected |
| **FP** | Legitimate access incorrectly flagged |
| **TN** | Correctly not flagged |
| **FN** | Real IDOR missed |

**Focus areas**

1. Horizontal IDOR accuracy  
2. Cross-role noise (self-access, intended admin)  
3. Confidence score reliability  
4. Noise from bad candidate values  

Document in `docs/TEST_RESULTS.md`.

---

## 6. Phase 4 — Real vulnerable labs

### Targets

| Lab | What to test | Priority | Status in this repo |
|-----|--------------|----------|---------------------|
| **OWASP Juice Shop** (local) | Basket path IDOR, JWT headers | High | **Executed** — see results |
| DVWA | User info / IDOR-style pages | High | Optional follow-up |
| PortSwigger Web Academy | Access control labs | High | Optional (needs account + lab VM) |
| bWAPP | Multiple IDOR challenges | Medium | Optional |
| Custom local apps | Edge cases | Medium | Covered by `idor_lab` |

### Protocol for each lab

1. Create config under `labs/<lab_name>/` (never commit live secrets).
2. Capture at least two roles / users.
3. Verify ground truth with curl/httpx.
4. Run scan with `--report` and `--html-report`.
5. Classify TP/FP/FN.
6. Update `TEST_RESULTS.md`.

### Juice Shop quick path

```bash
# Juice Shop must already be running on 127.0.0.1:3000
python labs/juice_shop/setup_and_scan.py
```

See `labs/juice_shop/README.md`.

---

## 7. Phase 5 — Edge cases & robustness

### Checklist

- [x] Numeric IDs  
- [ ] UUIDs (unit patterns only — expand lab)  
- [x] Sequential / patterned IDs  
- [x] Path parameters (`/resource/{id}`)  
- [ ] JSON body parameters (code support; dedicated lab case next)  
- [x] Missing or invalid cookies / sessions  
- [x] 403 / 404 / 401 responses  
- [ ] Redirects  
- [ ] Very large responses  
- [ ] Rate limiting (429)  
- [x] Empty / malformed / missing config files  
- [x] Non-existent parameters / IDs  
- [x] Noisy candidate values  

### Success criteria

- Tool does not crash  
- Clear error messages  
- Rate limiting (`--delay`) works  
- Path params require `{name}` in URL  

---

## 8. Phase 6 — Usability & reporting

### Checklist

- [x] CLI help is clear  
- [x] Error messages are actionable  
- [x] JSON report is complete  
- [x] HTML report is readable  
- [x] Confidence scores visible  
- [x] `cookie_file` works  
- [x] Header-based sessions (JWT) work  
- [x] Multi-parameter scanning supported in config  

---

## 9. Phase 7 — Advanced features (product backlog)

- [x] Ownership map (`--own-ids` / `scan.own_ids`) — **v0.4.0**  
- [x] Privileged role handling (`--privileged-roles`) — **v0.4.0**  
- [x] Better candidate filtering (exclude field names / dates) — **v0.4.0**  
- [x] Minimum confidence threshold (`--min-confidence`)  
- [ ] Horizontal-only mode refinements  
- [ ] First-class JWT helpers (beyond raw headers)  
- [ ] CSRF token handling  
- [ ] Non-zero exit code when high-confidence findings exist  

---

## 10. How to document results

For every significant campaign, update `docs/TEST_RESULTS.md` with:

1. Date and version  
2. Target description and authorization statement  
3. Commands used  
4. Ground truth  
5. Summary tables (TP / FP / TN / FN)  
6. Strengths  
7. Limitations  
8. Recommendations  
9. Artifact index  

Tone: professional, honest, portfolio-ready. Prefer evidence over marketing language.

---

## 11. Recommended execution order

1. `pytest -q`  
2. Re-run local lab suite; confirm still matches report narrative  
3. Juice Shop (or other authorized local app)  
4. Document accuracy carefully  
5. Prioritize product fixes for ownership / privileged roles  
6. Expand edge-case matrix  

---

## 12. Authorization rule

**Only test systems you own or have explicit written permission to test.**

Default lab traffic stays on `127.0.0.1`. Never point AccessProbe at production or third-party assets without a signed scope.

---

## 13. Quick reference

```bash
# Unit tests
pytest -q

# Local lab
python labs/idor_lab/server.py 8765
accessprobe scan --config labs/idor_lab/scan_vuln.yaml --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml --report labs/results/secure.json
accessprobe scan --config labs/idor_lab/scan_orders.yaml --report labs/results/orders.json
accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"

# Juice Shop (local)
python labs/juice_shop/setup_and_scan.py
```

---

**End of Test Plan**
