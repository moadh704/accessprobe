# AccessProbe — Validation Report

| Field | Value |
|-------|--------|
| **Product** | AccessProbe v0.3.0 |
| **Report date** | 2026-08-05 |
| **Tester** | Repository maintainer (authorized local testing only) |
| **Environment** | Windows 10 · Python 3.14 · Node.js 24 · `127.0.0.1` only |
| **Scope** | Local IDOR lab + OWASP Juice Shop (local install) |
| **Authorization** | All targets owned/controlled by the tester. No external systems scanned. |

---

## 1. Executive summary

AccessProbe was validated end-to-end against a controlled multi-user lab and against a local **OWASP Juice Shop** instance. Results show:

| Capability | Verdict | Notes |
|------------|---------|--------|
| Unit / regression suite | **Pass** | **28/28** tests green |
| Horizontal IDOR (same role, other object IDs) | **Strong** | High-confidence true positives on broken endpoints and Juice Shop baskets |
| Correct ACL (403 on foreign objects) | **Strong** | Foreign IDs on the secure lab endpoint were **not** flagged |
| Cross-role analysis | **Needs triage** | Self-access and intended admin access can raise leads |
| Parameter discovery | **Pass** | Query / form / link / JS parameters extracted from the lab homepage |
| Path parameters + Bearer JWT | **Pass** | Juice Shop `/rest/basket/{id}` with `Authorization` headers |
| CLI / reports / config | **Pass** | Actionable errors, JSON + HTML reports, `cookie_file` support |
| Candidate extraction noise | **Partial** | Occasional non-ID candidates; usually true negatives or low-value 200s |

**Bottom line for reviewers:** Horizontal object-level authorization testing is reliable enough for portfolio demonstration and authorized lab work. Cross-role findings should be reviewed manually until ownership maps and privileged-role handling land (see roadmap in `TEST_PLAN.md`).

---

## 2. Methodology

### 2.1 Phases executed

Aligned with [`docs/TEST_PLAN.md`](TEST_PLAN.md):

1. **Unit tests** — `pytest -q`
2. **Local IDOR laboratory** — `labs/idor_lab/`
3. **Accuracy analysis** — TP / FP / TN / FN classification
4. **Real vulnerable lab** — local OWASP Juice Shop 19.2.1 on port 3000
5. **Edge cases & robustness** — bad config, missing auth, CLI flags, path params
6. **Usability & reporting** — help text, JSON/HTML report structure, exit behavior

### 2.2 Classification legend

| Code | Meaning |
|------|---------|
| **TP** | Real authorization flaw correctly reported |
| **FP** | Legitimate access incorrectly reported as vulnerable |
| **TN** | Correctly *not* reported (denied or irrelevant) |
| **FN** | Real flaw missed or under-scored |

### 2.3 Ground truth

Every lab assertion was verified with `curl` / `httpx` **before** trusting the scanner output.

---

## 3. Phase 1 — Unit tests

```text
$ python -m pip install -e ".[dev]"
$ python -m pytest -q
............................                                         [100%]
28 passed in ~8s
```

| Module area | Covered |
|-------------|---------|
| Config / cookie files | Yes |
| Session manager | Yes |
| Detector confidence logic | Yes |
| Tester horizontal + cross-role | Yes |
| Discovery | Yes |
| Reporter | Yes |
| CLI wiring | Yes |

**Status:** Pass.

---

## 4. Phase 2 — Local IDOR laboratory

### 4.1 Target matrix

| Endpoint | ACL design | Expectation for scanner |
|----------|------------|-------------------------|
| `GET /vuln/profile?user_id=N` | Broken — any authed user can read any profile | Horizontal TPs |
| `GET /secure/profile?user_id=N` | Correct — own profile or admin | Quiet on foreign user IDs for non-admins |
| `GET /orders?order_id=N` | Broken object-level auth | Horizontal TPs |

**Sessions**

| Cookie `session=` | user_id | Role |
|-------------------|---------|------|
| `alice` | 1 | user |
| `bob` | 2 | user |
| `admin` | 3 | admin |

**Start lab**

```bash
python labs/idor_lab/server.py 8765
```

### 4.2 Manual ground truth (curl)

| Request | HTTP status | Interpretation |
|---------|-------------|----------------|
| alice → `/vuln/profile?user_id=2` | **200** + Bob’s PII | Real horizontal IDOR |
| alice → `/secure/profile?user_id=2` | **403** | ACL working |
| alice → `/secure/profile?user_id=1` | **200** | Self-access OK |
| alice → `/orders?order_id=101` | **200** | Broken order ACL |

### 4.3 Scan commands

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05

accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05

accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"
```

Artifacts: `labs/results/*` (JSON, HTML, console captures).

---

## 5. Phase 3 — Accuracy analysis (local lab)

### 5.1 Vulnerable profile (`scan_vuln.yaml`)

| Finding (summary) | Conf. | Class | Rationale |
|-------------------|-------|-------|-----------|
| alice → `user_id=2` (horizontal) | **1.00** | **TP** | Confirmed IDOR; private notes of Bob returned |
| bob → `user_id=1` | 0.72 | **TP** | Cross-user read of Alice |
| bob → `user_id=2` (own profile) | 0.96 | **FP** | Self-access without ownership model |
| admin → alternate IDs | 0.72–0.96 | **TP** | Broken endpoint; admin is still “any authed user” |
| Non-existent / garbage IDs (404/400) | 0.00 | **TN** | Correctly ignored |

**Scanner summary:** 5 potential IDORs flagged (includes the self-access FP).

### 5.2 Secure profile (`scan_secure.yaml`)

| Finding (summary) | Conf. | Class | Rationale |
|-------------------|-------|-------|-----------|
| alice → `user_id=2` | — | **TN** | 403, not flagged |
| bob → `user_id=1` | — | **TN** | 403, not flagged |
| bob → `user_id=2` (own) | 0.96 | **FP** | Self-access |
| admin → `user_id=1` / `2` | 0.72–0.96 | **FP*** | *Intended privilege* — tool has no privileged-role model |

**Takeaway:** Horizontal enforcement on a correct ACL is excellent. Cross-role noise is the main accuracy gap.

### 5.3 Orders (`scan_orders.yaml`)

All horizontal mutations of `order_id` that returned **200** were flagged (confidence up to **1.00**). Classified **TP** against the intentionally broken endpoint.

Noise note: candidate extraction occasionally injects field names (e.g. `owner_user_id`) as values; responses still 200 on this broken route so they inflate finding counts.

### 5.4 Discovery

From `GET /` with `session=alice`:

| Name | Location | Source type |
|------|----------|-------------|
| `user_id` | query | Form / link |
| `account_id` | query | Data attribute |
| `order_id` | query | Link |
| `id` | body | JavaScript |

**Status:** Pass (4 parameters).

---

## 6. Phase 4 — OWASP Juice Shop (local)

| Field | Value |
|-------|--------|
| **App** | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) 19.2.1 |
| **Host** | `http://127.0.0.1:3000` (local install under `~/juice-shop`) |
| **Auth** | JWT Bearer tokens via session `headers` |
| **Primary test** | Shopping basket path IDOR — `GET /rest/basket/{id}` |

### 6.1 Setup (reproducible)

```bash
# Terminal A
cd juice-shop && npm start

# Terminal B — creates two users, writes YAML (tokens stay local)
python labs/juice_shop/setup_and_scan.py
# or follow labs/juice_shop/README.md
```

Live tokens are **not** committed. Generated configs with secrets are gitignored; a template is provided.

### 6.2 Ground truth

| Actor | Action | Status | Result |
|-------|--------|--------|--------|
| alice | `GET /rest/basket/{alice_bid}` | 200 | Own basket |
| alice | `GET /rest/basket/{bob_bid}` | **200** | **Confirms classic Juice Shop basket IDOR** |

### 6.3 AccessProbe results (basket path IDOR)

Config shape:

```yaml
scan:
  target:
    url: "http://127.0.0.1:3000/rest/basket/{id}"
  parameters:
    - name: id
      location: path
      value: "<alice_basket_id>"
```

| Finding (summary) | Conf. | Class | Notes |
|-------------------|-------|-------|-------|
| alice → bob’s basket id (e.g. 8→9) | **1.00** | **TP** | Horizontal IDOR; body similarity ~0.96 |
| alice → nearby numeric baskets | 0.75–1.00 | **TP / partial** | Other baskets also world-readable when they exist |
| alice → junk path values still 200 | 0.75 | **Noise / soft-TP** | Juice Shop may return empty-ish success shells; triage needed |
| bob → alice’s basket (cross-role) | **0.00** in one run | **FN risk** | Same status 200 but detector scored below threshold when body differed from baseline |

**Scanner summary (representative run):** 8 vulnerable findings out of 13 rows; strongest signal is same-role horizontal access to another shopper’s basket.

**Artifacts:** `labs/results/juice_shop/basket.json`, `basket.html`, `basket.console.txt`, `setup_meta.json`.

### 6.4 Secondary probe — `/api/Users/{id}`

Path probes against `/api/Users/{id}` returned server errors (500) in this Juice Shop build/config for the values tried. Documented as **inconclusive** for object-level user IDOR; basket remains the solid Juice Shop demonstration path.

---

## 7. Phase 5 — Edge cases & robustness

| Case | Result | Notes |
|------|--------|-------|
| Numeric IDs | Pass | Lab + Juice Shop |
| Path parameters | Pass | Requires URL placeholder `{name}` |
| Missing / invalid config file | Pass | Clear `Config error: Config file not found` |
| No session cookies (lab) | Pass | Uniform 401 · 0 false IDORs |
| `--min-confidence 0.9` | Pass | Filters lower-confidence leads |
| `--no-horizontal` | Pass | Cross-role only path still runs |
| `--delay` | Pass | Rate limiting between requests |
| Candidate junk values | Partial | Field names / dates can appear; often TN or low value |
| UUID-style IDs | Not stressed in this run | Covered by unit-level extraction patterns; future lab case |
| JSON body / header / cookie locations | Supported in code | Unit coverage; dedicated lab cases recommended next |
| 429 / huge responses | Not simulated | Planned |

**No crashes** observed during the full campaign. Exit codes remain 0 for completed scans (including “findings present”).

---

## 8. Phase 6 — Usability & reporting

| Check | Result |
|-------|--------|
| `accessprobe --help` / `scan --help` | Clear, complete flags |
| Version flag | `AccessProbe 0.3.0` |
| Error messages | Actionable (missing config, bad paths) |
| JSON report | Structured: totals, per-finding confidence, evidence, statuses |
| HTML report | Readable tables, severity coloring, suitable for portfolio screenshots |
| `cookie_file` relative to config | Works for lab sessions |
| Multi-role YAML + Bearer headers | Works for Juice Shop |

---

## 9. Strengths observed

1. **Horizontal IDOR is the product’s sweet spot** — high confidence, low false noise when the ACL returns 403 correctly.
2. **Multi-auth flexibility** — cookie files *and* header-based JWT sessions.
3. **Path IDOR support** — works when the URL uses `{param}` placeholders.
4. **Professional reporting** — JSON for automation, HTML for demos and write-ups.
5. **Reproducible labs** — self-contained IDOR server + documented Juice Shop workflow.
6. **Solid unit baseline** — 28 tests protect detector/tester regressions.

---

## 10. Limitations & honest gaps

| Limitation | Impact | Mitigation / roadmap |
|------------|--------|----------------------|
| No ownership map | Self-access flagged as vulnerable (FP) | `--own-ids` / config ownership |
| No privileged-role awareness | Intended admin reads flagged (FP) | `--privileged-roles` |
| Cross-role similarity gate | Can under-score some true cross-user 200s (FN risk on Juice Shop bob→alice) | Tune detector when baseline bodies differ by design |
| Candidate extraction noise | Extra finding rows | Filter non-numeric noise; exclude JSON keys |
| Live third-party labs not in this report | DVWA / PortSwigger / bWAPP pending | Phase 4 expansion in plan |
| Secrets hygiene | Generated JWT configs must stay local | gitignore + setup script |

---

## 11. Metrics snapshot (this campaign)

| Metric | Value |
|--------|-------|
| Unit tests | **28/28 passed** |
| Local lab endpoints exercised | 3 (+ discovery homepage) |
| Juice Shop endpoints with solid ground truth | Basket path IDOR |
| Critical false positives on *secure horizontal* paths | **0** |
| Known FP categories | Self-access, privileged admin |
| Real-world lab TP (Juice Shop basket) | **Yes (conf. 1.00)** |

---

## 12. Recommendations (product)

Priority order for the next accuracy sprint:

1. **Ownership awareness** — suppress findings where `tested_value` is known to belong to the testing role.
2. **Privileged roles** — never treat intended admin access as IDOR by default.
3. **Smarter candidates** — prefer numeric/UUID IDs; drop field-name tokens.
4. **Cross-role scoring** — when foreign role receives 200 for original object ID, score as potential IDOR even if body ≠ baseline (different user context).
5. **Exit codes** — optional non-zero exit when high-confidence findings exist (CI-friendly).

---

## 13. How to reproduce this report

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e ".[dev]"
pytest -q

# Lab
python labs/idor_lab/server.py 8765
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json
accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json
accessprobe discover --url http://127.0.0.1:8765/ --cookie "session=alice"

# Juice Shop (separate local install on :3000)
python labs/juice_shop/setup_and_scan.py
```

---

## 14. Authorization & ethics

All testing described in this document was performed against **local processes bound to `127.0.0.1`**, owned by the tester:

- AccessProbe IDOR lab (`labs/idor_lab`)
- Locally installed OWASP Juice Shop

No production systems, third-party tenants, or out-of-scope hosts were scanned. AccessProbe is intended for **authorized security testing and education only**.

---

## 15. Artifact index

| Path | Description |
|------|-------------|
| `labs/results/vuln.json` / `.html` | Broken profile scan |
| `labs/results/secure.json` / `.html` | Correct ACL scan |
| `labs/results/orders.json` | Broken orders scan |
| `labs/results/*.console.txt` | CLI transcripts |
| `labs/results/juice_shop/basket.*` | Juice Shop basket IDOR |
| `labs/results/juice_shop/setup_meta.json` | Basket IDs / ground-truth flags (no secrets) |
| `docs/TEST_PLAN.md` | Full testing program |

---

*End of validation report — AccessProbe v0.3.0*
