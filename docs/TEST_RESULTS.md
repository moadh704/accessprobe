# AccessProbe Test Results

**Date:** 2026-08-05  
**Version:** 0.3.0  
**Scope:** Local authorized multi-user IDOR laboratory only

---

## 1. Summary

AccessProbe was installed, unit-tested, and executed end-to-end against a controlled local IDOR lab. Results:

| Capability                        | Outcome                                      |
|-----------------------------------|----------------------------------------------|
| Install / CLI / exit codes        | Pass                                         |
| Automated pytest suite            | 28/28 passed                                 |
| Horizontal IDOR detection         | Strong (true positives confirmed via curl)   |
| Correct ACL (403 on foreign IDs)  | Strong (no horizontal false positives)       |
| Cross-role testing                | Noisy — flags legitimate self-access and intended admin access |
| Config, cookie files, reports     | Pass                                         |
| Parameter discovery               | Pass (4 parameters from lab HTML)            |

**Key takeaway:** Horizontal IDOR detection is reliable when baselining as a low-privilege user and mutating object IDs. Cross-role findings should be treated as leads requiring human review, especially when the test role is admin or is accessing its own resource.

---

## 2. Environment

| Item     | Value                                      |
|----------|--------------------------------------------|
| OS       | Linux                                      |
| Python   | 3.12.3                                     |
| Package  | accessprobe 0.3.0 (editable install)       |
| Tools    | pytest, ruff, mypy, curl                   |
| Target   | Local lab only (`http://127.0.0.1:8765`)   |

### Pre-target health checks

```text
accessprobe --version   → AccessProbe 0.3.0
pytest                  → 28 passed
accessprobe scan (no args) → exit 1, clean error message
```

---

## 3. Laboratory Target

### Location

```text
labs/idor_lab/
  server.py
  cookies/{alice,bob,admin}.txt
  scan_vuln.yaml
  scan_secure.yaml
  scan_orders.yaml
```

### Starting the lab

```bash
python labs/idor_lab/server.py 8765
```

Sessions (Cookie: `session=...`):

| Cookie value | user_id | Role  |
|--------------|---------|-------|
| alice        | 1       | user  |
| bob          | 2       | user  |
| admin        | 3       | admin |

### Endpoints

| Path                          | Behavior                                      |
|-------------------------------|-----------------------------------------------|
| `GET /vuln/profile?user_id=N` | Broken ACL — any authenticated user can read any profile |
| `GET /secure/profile?user_id=N` | Correct ACL — own profile only; admin can read all |
| `GET /orders?order_id=N`      | Broken object-level authorization             |
| `GET /`                       | HTML containing discoverable parameters       |
| `GET /health`                 | Liveness check                                |

---

## 4. Ground Truth (curl)

| Request                              | Expected              | Observed                  | Notes                  |
|--------------------------------------|-----------------------|---------------------------|------------------------|
| alice → `/vuln/profile?user_id=1`    | 200 (own data)        | 200 Alice                 | Correct                |
| alice → `/vuln/profile?user_id=2`    | 200 (foreign, vuln)   | 200 Bob + secrets         | Confirmed IDOR         |
| alice → `/secure/profile?user_id=2`  | 403                   | 403                       | Correct ACL            |
| admin → `/secure/profile?user_id=2`  | 200 (admin privilege) | 200 Bob                   | Intended access        |

---

## 5. Scan Results

All scans used configs under `labs/idor_lab/`, `--delay 0.05`, and wrote reports to `labs/results/`.

### 5.1 Vulnerable profile (`scan_vuln.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05
```

| Metric             | Value |
|--------------------|-------|
| Exit code          | 0     |
| Total findings     | 20    |
| Marked vulnerable  | 5     |

Notable findings:

| Finding                                      | Confidence | Ground truth              | Classification |
|----------------------------------------------|------------|---------------------------|----------------|
| alice → `user_id=2` (horizontal)             | 1.00 HIGH  | 200 with Bob secrets      | TP             |
| bob → `user_id=1` (cross-role)               | 0.72 LOW   | bob can read Alice        | TP             |
| bob → `user_id=2` (cross-role)               | 0.96 HIGH  | bob’s own profile         | FP (self-access) |
| admin → alternate IDs                        | 0.96 HIGH  | anyone can read (vuln)    | TP             |
| Non-existent IDs / garbage candidates        | 0.00       | 404 / 400                 | TN             |

Horizontal IDOR detection performed as expected on the broken target.

### 5.2 Secure profile (`scan_secure.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05
```

| Metric             | Value |
|--------------------|-------|
| Exit code          | 0     |
| Marked vulnerable  | 3 (all cross-role; 0 horizontal) |

Notable findings:

| Finding                          | Confidence | Ground truth             | Classification          |
|----------------------------------|------------|--------------------------|-------------------------|
| alice → `user_id=2` horizontal   | —          | 403                      | TN (not flagged)        |
| bob → `user_id=1`                | —          | 403                      | TN                      |
| bob → `user_id=2` cross-role     | 0.96 HIGH  | bob own profile          | FP (authorized self-access) |
| admin → `user_id=1` / `2`        | 0.72–0.96  | intended admin access    | FP (no privilege model) |

Horizontal ACL was correctly respected. Cross-role comparison continues to surface legitimate access as findings.

### 5.3 Secure with `--no-horizontal`

Horizontal tests omitted as designed. Remaining flags were self-access and admin access (false leads).

### 5.4 Orders (`scan_orders.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05
```

| Metric             | Value     |
|--------------------|-----------|
| Exit code          | 0         |
| Marked vulnerable  | 11 / 11   |

All horizontal mutations of `order_id` returned 200 with similar content and were correctly flagged. Endpoint is intentionally broken → true positives for object-level authorization failure.

### 5.5 Parameter discovery

```bash
accessprobe discover --url 'http://127.0.0.1:8765/' --cookie 'session=alice'
```

- Exit code: 0  
- Parameters found: 4 (`user_id`, `account_id`, `order_id`, `id`)

---

## 6. Accuracy Summary

| Scenario                        | TP | FP | TN | Notes                              |
|---------------------------------|----|----|----|------------------------------------|
| Vuln horizontal foreign ID      | ✓  | 0  | ✓  | Primary strength                   |
| Secure horizontal foreign ID    | 0  | 0  | ✓  | Correctly quiet                    |
| Cross-role self-access          | 0  | ✓  | —  | Known limitation                   |
| Cross-role intended admin       | 0  | ✓  | —  | Requires role/ownership modeling   |
| Orders broken object auth       | ✓  | 0  | —  | Clean detection                    |

Horizontal IDOR accuracy on this lab is high. Naive multi-role differential testing without ownership or privilege context remains moderate and needs triage.

---

## 7. Observed Strengths

- Cookie files via `cookie_file` (paths relative to config)
- Multi-session YAML configuration
- Horizontal IDOR mutation loop (same role, alternate object IDs)
- Status-aware analysis (403/404 not treated as success)
- Structured JSON and HTML reports with confidence scores
- Parameter discovery from forms, links, data attributes, and inline JS
- Stable CLI behavior (clean exit codes, no post-scan crashes)

---

## 8. Limitations

1. No ownership model — cannot distinguish “bob viewing id=2 is authorized.”
2. No privileged-role handling — intended admin access is flagged.
3. Candidate extraction can surface field names or incidental numeric values, producing noise rows (usually true negatives).
4. Authentication beyond simple cookies (JWT, CSRF, multi-step login) was not exercised.
5. Third-party applications (e.g. Juice Shop) were not tested in this environment.

---

## 9. Recommendations

1. Support an optional ownership map (e.g. `--own-ids role=id`) so self-access is not flagged.
2. Add privileged-role handling (e.g. `--privileged-roles admin`) to suppress or downgrade intended access.
3. Improve candidate filtering: prefer numeric/UUID values and exclude clear field names.
4. Prioritize horizontal findings in the default CLI summary over cross-role rows.
5. Optionally hide findings below `--min-confidence` unless `--show-all` is supplied.

---

## 10. Reproduction

```bash
# Terminal 1
python labs/idor_lab/server.py 8765

# Terminal 2
pip install -e ".[dev]"
pytest -q

accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json

accessprobe discover --url http://127.0.0.1:8765/ --cookie 'session=alice'
```

Manual verification:

```bash
curl -s -H 'Cookie: session=alice' 'http://127.0.0.1:8765/vuln/profile?user_id=2'
curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: session=alice' \
  'http://127.0.0.1:8765/secure/profile?user_id=2'
```

---

## 11. Artifacts

| Path                        | Description                          |
|-----------------------------|--------------------------------------|
| `labs/idor_lab/`            | Reproducible lab                     |
| `labs/results/*.json`       | Machine-readable scan reports        |
| `labs/results/*.html`       | HTML reports                         |
| `labs/results/*.console.txt`| Full CLI output captures             |

---

## 12. Authorization

All testing was performed against a local laboratory process started by the operator on `127.0.0.1`. No external or production systems were scanned.
