# AccessProbe — Validation Report

| Field | Value |
|-------|--------|
| **Product** | AccessProbe **v0.4.0** |
| **Report date** | 2026-08-05 |
| **Tester** | Repository maintainer (authorized local testing only) |
| **Environment** | Windows 10 · Python 3.14 · Node.js 24 · `127.0.0.1` only |
| **Scope** | Local IDOR lab + OWASP Juice Shop (local install) |
| **Authorization** | All targets owned/controlled by the tester. No external systems scanned. |

<p align="center">
  <img src="assets/accuracy-before-after.png" alt="Before/after accuracy comparison" width="820" />
</p>

---

## 1. Executive summary

AccessProbe was validated end-to-end against a controlled multi-user lab and a local **OWASP Juice Shop** instance. Version **0.4.0** adds **ownership maps** and **privileged-role** handling that eliminate the main false-positive classes observed in v0.3.

| Capability | Verdict | Notes |
|------------|---------|--------|
| Unit / regression suite | **Pass** | **33/33** tests green |
| Horizontal IDOR (same role, other object IDs) | **Strong** | High-confidence TPs on broken endpoints + Juice Shop baskets |
| Correct ACL (403 on foreign objects) | **Strong** | Foreign IDs not flagged |
| Self-access / intended admin (with context) | **Strong** | Suppressed via `own_ids` + `privileged_roles` → **0 FPs** on secure lab |
| Cross-role without context | Manual triage | Still recommend ownership map for production use |
| Parameter discovery | **Pass** | Lab homepage parameters found |
| Path parameters + Bearer JWT | **Pass** | Juice Shop `/rest/basket/{id}` |
| CLI / reports / config | **Pass** | JSON + HTML + clear errors |

**Bottom line for reviewers:** AccessProbe is a focused, demable authorization-testing tool with reproducible labs, honest metrics, and a clear accuracy improvement story (v0.3 → v0.4).

---

## 2. Headline before / after (v0.3 → v0.4)

Target: `GET /secure/profile?user_id=N` (correct ACL — own profile or admin).

| Metric | v0.3 (no context) | v0.4 (`own_ids` + `privileged_roles: admin`) |
|--------|-------------------|-----------------------------------------------|
| alice → foreign id=2 (403) | TN | TN |
| bob → own id=2 (200) | **FP** | **Suppressed (self-access)** |
| admin → id=1/2 (200) | **FP** | **Suppressed (privileged)** |
| **Vulnerable findings reported** | **3** | **0** |

Broken endpoint `GET /vuln/profile` still reports real IDORs (e.g. alice → user_id=2 at confidence **1.00**). Self-access for bob→2 is suppressed; foreign access remains.

Artifacts: `labs/results/v0.4/` (JSON, HTML, console).

---

## 3. Methodology

Aligned with [`TEST_PLAN.md`](TEST_PLAN.md):

1. Unit tests — `pytest -q`  
2. Local IDOR laboratory — `labs/idor_lab/`  
3. Accuracy analysis — TP / FP / TN / FN  
4. Real vulnerable lab — OWASP Juice Shop 19.2.1  
5. Edge cases & robustness  
6. Usability & reporting  
7. **Accuracy product fix** — ownership + privileged roles (v0.4)

| Code | Meaning |
|------|---------|
| **TP** | Real authorization flaw correctly reported |
| **FP** | Legitimate access incorrectly reported |
| **TN** | Correctly not reported |
| **FN** | Real flaw missed |

Ground truth verified with `curl` / `httpx` before trusting scanner output.

---

## 4. Phase 1 — Unit tests

```text
$ pytest -q
.................................                                 [100%]
33 passed in ~7.5s
```

Coverage includes detector rules, ownership/privileged filters, candidate noise filtering, CLI version, config, discovery, reporter, and mock-server integration.

---

## 5. Phase 2–3 — Local IDOR lab (v0.4)

### Target matrix

| Endpoint | ACL | Expectation |
|----------|-----|-------------|
| `/vuln/profile?user_id=N` | Broken | Horizontal TPs |
| `/secure/profile?user_id=N` | Correct (own + admin) | **0 FPs** with context |
| `/orders?order_id=N` | Broken | Horizontal TPs |

| Cookie | user_id | Role |
|--------|---------|------|
| alice | 1 | user |
| bob | 2 | user |
| admin | 3 | admin |

### Config context (v0.4)

```yaml
own_ids:
  alice: ["1"]
  bob: ["2"]
  admin: ["3"]
privileged_roles:   # used on secure scan
  - admin
```

### Commands

```bash
python labs/idor_lab/server.py 8765

accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/v0.4/vuln.json --html-report labs/results/v0.4/vuln.html

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/v0.4/secure.json --html-report labs/results/v0.4/secure.html

accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/v0.4/orders.json
```

### Ground truth (curl)

| Request | Status | Meaning |
|---------|--------|---------|
| alice → `/vuln/profile?user_id=2` | **200** + Bob PII | Real IDOR |
| alice → `/secure/profile?user_id=2` | **403** | ACL OK |
| alice → `/secure/profile?user_id=1` | **200** | Self OK |

### Results — vulnerable profile

| Finding | Conf. | Class |
|---------|-------|-------|
| alice → user_id=2 (horizontal) | **1.00** | **TP** |
| bob → user_id=1 | 0.84 | **TP** |
| bob → user_id=2 (own) | — | **Suppressed** (self-access) |
| admin → user_id=1 / 2 | 0.84–0.96 | **TP** on broken ACL (admin not privileged in vuln config) |
| 404 / invalid IDs | 0.00 | **TN** |

**Scanner summary:** 4 potential IDORs (all real or broken-ACL access).

### Results — secure profile

| Finding | Class |
|---------|-------|
| alice → user_id=2 (403) | **TN** |
| bob → user_id=1 (403) | **TN** |
| bob → user_id=2 | **Suppressed** self-access |
| admin → user_id=1 / 2 | **Suppressed** privileged |
| **Total vulnerable findings** | **0** |

### Results — orders

Horizontal mutations on non-owned order IDs flagged (confidence up to **1.00**). Owned IDs (100/101 for alice) suppressed. Broken endpoint remains loud — correct for this target.

### Discovery

4 parameters from lab homepage (`user_id`, `account_id`, `order_id`, `id`).

---

## 6. Phase 4 — OWASP Juice Shop (local)

| Field | Value |
|-------|--------|
| App | OWASP Juice Shop 19.2.1 |
| Host | `http://127.0.0.1:3000` |
| Auth | JWT Bearer session headers |
| Primary test | `GET /rest/basket/{id}` path IDOR |

### Ground truth

| Call | Status |
|------|--------|
| alice → own basket | 200 |
| alice → bob’s basket | **200** (confirmed classic basket IDOR) |

### AccessProbe

| Finding | Conf. | Class |
|---------|-------|-------|
| alice → bob basket id | **1.00** | **TP** |
| Nearby numeric baskets (200) | 0.75–1.00 | TP / triage |

Path URLs **must** use `{id}` placeholder. Setup helper: `python labs/juice_shop/setup_and_scan.py` (tokens gitignored).

Artifacts: `labs/results/juice_shop/`.

---

## 7. Phase 5–6 — Edge cases & usability

| Case | Result |
|------|--------|
| Numeric + path params | Pass |
| Missing config | Clear error |
| No session (lab) | 401 · 0 false IDORs |
| `--own-ids` / `--privileged-roles` | Pass |
| Candidate noise (field names / dates) | Reduced in v0.4 |
| JSON / HTML reports | Pass |
| CLI help | Pass |

No crashes during the campaign.

---

## 8. Strengths

1. Horizontal IDOR detection is reliable and demable.  
2. **v0.4 ownership + privileged roles** turn a noisy secure scan into a clean **0 FP** result.  
3. Cookie files, JWT headers, and path parameters cover real targets (Juice Shop).  
4. Reproducible labs + portfolio-grade documentation.  
5. Growing automated test suite (33 tests).

---

## 9. Remaining limitations

| Limitation | Impact | Status |
|------------|--------|--------|
| Context optional | Without `own_ids`, self-access can still raise leads | By design — document in config |
| Cross-role body mismatch | Rare FN when 200 bodies differ a lot | Detector improved; monitor |
| UUID-heavy apps | Less lab coverage | Future |
| DVWA / PortSwigger | Not in this campaign | Optional next |
| Secrets | Live JWTs must stay local | gitignored |

---

## 10. Metrics snapshot

| Metric | Value |
|--------|-------|
| Tests | **33/33** |
| Secure ACL vulnerable findings (v0.4) | **0** |
| Broken profile horizontal TP | conf. **1.00** |
| Juice Shop basket TP | conf. **1.00** |
| Version | **0.4.0** |

---

## 11. How to reproduce

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e ".[dev]"
pytest -q

python labs/idor_lab/server.py 8765
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/v0.4/vuln.json --html-report labs/results/v0.4/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/v0.4/secure.json

# Optional: local Juice Shop on :3000
python labs/juice_shop/setup_and_scan.py
```

---

## 12. Authorization & ethics

All testing used **local processes on `127.0.0.1`** owned by the tester. No production or third-party systems were scanned. AccessProbe is for **authorized** security testing and education only.

---

## 13. Artifact index

| Path | Description |
|------|-------------|
| `docs/assets/accuracy-before-after.png` | Before/after accuracy card |
| `docs/assets/report-vuln.png` | HTML report screenshot (vuln) |
| `docs/assets/demo-accuracy.mp4` | Short demo clip of the accuracy card |
| `labs/results/v0.4/*` | v0.4 lab scan outputs |
| `labs/results/juice_shop/*` | Juice Shop basket scan |
| `docs/TEST_PLAN.md` | Full testing program |

---

*End of validation report — AccessProbe v0.4.0*
