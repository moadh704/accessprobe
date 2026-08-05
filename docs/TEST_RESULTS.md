# AccessProbe Test Results

**Date:** 2026-08-05  
**Version:** 0.3.0  
**Commit:** `8407c3d` (pre-report) / this commit adds lab + docs  
**Tester:** automated + manual verification (local authorized lab only)  
**Overall grade:** **B+ — works well on real HTTP targets for horizontal IDOR; cross-role needs human triage**

---

## 1. Executive summary

AccessProbe was installed, unit-tested, and run end-to-end against a **local multi-user IDOR lab** (authorized, under operator control). The tool:

| Capability | Result |
|------------|--------|
| Install / CLI / exit codes | Pass |
| Automated pytest suite | **28/28 pass** |
| Detect horizontal IDOR (same user, other object IDs) | **Strong (true positives confirmed with curl)** |
| Correct ACL (403 on foreign IDs) | **Strong (no horizontal false positives)** |
| Cross-role scans | **Noisy** — flags legitimate “other user views own object” and intended admin access |
| Config + cookie files + reports | Pass |
| Parameter discovery | Pass (4 params from HTML lab home) |
| Third-party / Juice Shop | **Skipped** — Docker CLI not functional in this environment |

**Bottom line:** For authorized assessments, AccessProbe is effective at finding **horizontal IDOR** when you baseline as a low-priv user and let it mutate object IDs. Treat **cross-role “Vulnerable: Yes”** as *leads*, not automatic bugs — especially when the test role is admin or is viewing its own resource.

---

## 2. Environment

| Item | Value |
|------|--------|
| OS | Linux |
| Python | 3.12.3 |
| Package | `accessprobe` 0.3.0 (editable install) |
| Tools | pytest, ruff, mypy, curl |
| Docker | Present at `/snap/bin/docker` but not usable (`docker --version` failed) |
| Target | Local lab `http://127.0.0.1:8765` only |

### Tool health (pre-target)

```text
accessprobe --version   → AccessProbe 0.3.0
pytest                  → 28 passed in ~4s
accessprobe scan (no args) → exit 1, clean error (no asyncio crash)
```

---

## 3. Target lab

### Location

```text
labs/idor_lab/
  server.py           # multi-user API
  cookies/{alice,bob,admin}.txt
  scan_vuln.yaml
  scan_secure.yaml
  scan_orders.yaml
```

### How to run the lab

```bash
python labs/idor_lab/server.py 8765
# Sessions (Cookie: session=...):
#   alice → user_id 1
#   bob   → user_id 2
#   admin → user_id 3 (role=admin)
```

### Endpoints

| Path | Behavior |
|------|----------|
| `GET /vuln/profile?user_id=N` | **Broken ACL** — any authenticated user can read any profile |
| `GET /secure/profile?user_id=N` | **Correct ACL** — own profile only; admin can read all |
| `GET /orders?order_id=N` | **Broken object auth** — any authed user can read any order |
| `GET /` | HTML with discoverable `user_id` / `order_id` / `account_id` |
| `GET /health` | Liveness |

---

## 4. Manual truth (curl ground truth)

| Request | Expected | Observed | Notes |
|---------|----------|----------|--------|
| alice → `/vuln/profile?user_id=1` | 200 own data | **200** Alice | OK |
| alice → `/vuln/profile?user_id=2` | 200 foreign (vuln) | **200** Bob + secrets | **Real IDOR** |
| alice → `/secure/profile?user_id=2` | 403 | **403** access denied | Correct ACL |
| admin → `/secure/profile?user_id=2` | 200 (admin) | **200** Bob | Intended privilege |

---

## 5. AccessProbe scan matrix

All scans used configs under `labs/idor_lab/`, delay `0.05s`, and wrote reports under `labs/results/`.

### 5.1 Vulnerable profile (`scan_vuln.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05
```

| Metric | Value |
|--------|-------|
| Exit code | **0** |
| Total findings | 20 |
| Marked vulnerable | **5** |
| Reports | `vuln.json`, `vuln.html` written |

#### Key findings vs truth

| Finding | Conf. | Manual truth | Label |
|---------|-------|--------------|-------|
| alice → `user_id=2` horizontal, status 200 | 1.00 HIGH | curl 200 Bob secrets | **TP** |
| bob → `user_id=1` cross-role, 200 | 0.72 LOW | bob can read Alice (vuln) | **TP** (broken ACL) |
| bob → `user_id=2` cross-role, 200 | 0.96 HIGH | bob’s **own** profile | **FP / noisy** (authorized self-access) |
| admin → alternate IDs, 200 | 0.96 HIGH | anyone can read (vuln) | **TP** for vuln app; would be FP on secure admin |
| Non-existent IDs 0/6/11 → 404 | 0.00 | not vulnerable | **TN** |
| Garbage candidates (`private_notes`, phone digits) | 0.00 | 400/404 | **TN** (noise values, correctly not flagged) |

**Verdict:** Horizontal IDOR detection works as intended on a broken target.

---

### 5.2 Secure profile (`scan_secure.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05
```

| Metric | Value |
|--------|-------|
| Exit code | **0** |
| Marked vulnerable | **3** (all cross-role; **0** horizontal) |

#### Key findings vs truth

| Finding | Conf. | Manual truth | Label |
|---------|-------|--------------|-------|
| alice → `user_id=2` horizontal | — | **403** | **TN** (not flagged) |
| bob → `user_id=1` | — | **403** | **TN** |
| bob → `user_id=2` cross-role | 0.96 HIGH | bob own profile (authorized) | **FP** |
| admin → `user_id=1` / `2` | 0.72–0.96 | admin intended access | **FP** (no role policy) |

**Verdict:** Secure horizontal ACL is respected. Cross-role comparison still raises false leads when another user successfully reads *their* object or when admin has legitimate access.

---

### 5.3 Secure with `--no-horizontal`

| Metric | Value |
|--------|-------|
| Exit code | **0** |
| Horizontal rows | Omitted (as designed) |
| Still flagged | bob own-id + admin access (**FP leads**) |

---

### 5.4 Orders (`scan_orders.yaml`)

```bash
accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05
```

| Metric | Value |
|--------|-------|
| Exit code | **0** |
| Marked vulnerable | **11 / 11** findings |

Horizontal mutations (`order_id` 101, 99, 105, …) all returned **200** with similar JSON → flagged HIGH. Manual expectation: endpoint is intentionally broken for any authed user → **TP** for object-level broken auth.

Note: candidate extraction also tried string `owner_user_id` as a value (still 200 on this dumb API). That’s **candidate noise**, not a detector false negative/positive on status logic.

---

### 5.5 Discover

```bash
accessprobe discover --url 'http://127.0.0.1:8765/' --cookie 'session=alice'
```

| Result | Detail |
|--------|--------|
| Exit code | **0** |
| Params found | **4**: `user_id` (form), `account_id` (data attr), `order_id` (link), `id` (JS) |

---

## 6. Accuracy rollup

Focusing on **high-signal rows** a human would care about:

| Scenario | TP | FP | TN | Notes |
|----------|----|----|----|-------|
| Vuln horizontal foreign ID | 1+ | 0 | many 404s | Primary win |
| Secure horizontal foreign ID | 0 | 0 | 1+ | Correctly quiet |
| Cross-role self-access | 0 | 1+ | — | Known limitation |
| Cross-role intended admin | 0 | 1+ | — | Needs allowlist / role policy |
| Orders broken object auth | many | 0* | — | *modulo silly string candidates |

**Practical accuracy for horizontal IDOR on this lab: excellent.**  
**Practical accuracy for naive multi-role diff without policy: moderate (needs triage).**

---

## 7. What works well on targets

1. Real cookies via `cookie_file` (paths relative to config).
2. Multi-session YAML configs.
3. Horizontal IDOR loop (same role, other IDs) — the most valuable signal.
4. Status-aware analysis (403/404 not treated as success).
5. JSON + HTML reports with confidence and evidence strings.
6. Discovery from HTML forms, links, `data-*`, and inline JS.
7. Stable CLI (exit 0 on success, exit 1 on misuse, no post-scan crash).

---

## 8. Limitations observed on targets

1. **No ownership model** — cannot know “bob viewing id=2 is OK.”
2. **No admin allowlist** — intended privileged access looks like a finding.
3. **Same-object both-200 with many keywords** still soft-flags (conf ~0.72) even when sharing may be intended.
4. **Candidate value extraction** can pull field *names* or phone-like numbers (`private_notes`, `10000000001`) → extra noise rows (usually TN).
5. **Docker/Juice Shop** not validated in this environment.
6. Auth beyond simple cookies (JWT refresh, CSRF, multi-step login) not exercised here.

---

## 9. Recommendations (product)

1. Add optional **`--own-ids role=id`** map so self-access is not flagged.
2. Add **`--privileged-roles admin`** to downgrade or skip intended admin access.
3. Prefer numeric/UUID candidates; filter response keys that are clearly field names.
4. Default CLI summary: show **horizontal findings first**, then cross-role.
5. Confidence gate in table: hide rows below `--min-confidence` entirely (optional `--show-all`).

---

## 10. How to re-run

```bash
# terminal 1
python labs/idor_lab/server.py 8765

# terminal 2
pip install -e ".[dev]"
pytest -q
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json
accessprobe discover --url http://127.0.0.1:8765/ --cookie 'session=alice'
```

Manual truth checks:

```bash
curl -s -H 'Cookie: session=alice' 'http://127.0.0.1:8765/vuln/profile?user_id=2'
curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: session=alice' \
  'http://127.0.0.1:8765/secure/profile?user_id=2'
```

---

## 11. Artifacts

| Path | Description |
|------|-------------|
| `labs/idor_lab/` | Reproducible vulnerable + secure lab |
| `labs/results/*.json` | Scan reports from this run |
| `labs/results/*.html` | HTML reports (vuln/secure) |
| `labs/results/*.console.txt` | Full CLI console captures |

---

## 12. Authorization statement

All target testing used a **local lab process started by the operator** on `127.0.0.1`. No third-party or production systems were scanned.
