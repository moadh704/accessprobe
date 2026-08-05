# AccessProbe — Testing Plan

**Version:** 0.3.0  
**Last Updated:** 2026-08-05  
**Purpose:** Systematic plan to validate accuracy, robustness, and usability of AccessProbe.

This document is designed so that a human or AI assistant can follow it step-by-step and produce consistent, reproducible results.

---

## 1. Goals

| Goal                              | Description                                      |
|-----------------------------------|--------------------------------------------------|
| Accuracy                          | Maximize true positives, minimize false positives |
| Reliability                       | Stable CLI, correct exit codes, no crashes       |
| Coverage                          | Support common IDOR patterns and parameter locations |
| Usability                         | Clear reports, good error messages, easy config  |
| Reproducibility                   | All tests can be re-run with the same results    |

---

## 2. Testing Phases Overview

| Phase | Name                        | Priority | Status        |
|-------|-----------------------------|----------|---------------|
| 1     | Unit Tests                  | Critical | Done (28/28)  |
| 2     | Local IDOR Lab              | Critical | Done          |
| 3     | Accuracy Analysis           | Critical | Done          |
| 4     | Real Vulnerable Labs        | High     | Pending       |
| 5     | Edge Cases & Robustness     | High     | Pending       |
| 6     | Usability & Reporting       | Medium   | Pending       |
| 7     | Advanced Features           | Medium   | Pending       |

---

## 3. Phase 1 — Unit Tests

### Commands

```bash
pip install -e ".[dev]"
pytest -q
pytest -v --tb=short
```

### Success Criteria

- All tests pass
- No warnings that indicate broken logic
- Coverage of core modules: models, session, config, detector, tester, discovery, reporter, cli

### Expected Result

```
28 passed
```

---

## 4. Phase 2 — Local IDOR Laboratory

### Location

```
labs/idor_lab/
```

### Start the lab

```bash
python labs/idor_lab/server.py 8765
```

### Sessions

| Cookie value | user_id | Role  |
|--------------|---------|-------|
| alice        | 1       | user  |
| bob          | 2       | user  |
| admin        | 3       | admin |

### Required Scans

```bash
# Vulnerable profile (should find horizontal IDORs)
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html --delay 0.05

# Secure profile (should be quiet on horizontal)
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json --html-report labs/results/secure.html --delay 0.05

# Orders (broken object-level auth)
accessprobe scan --config labs/idor_lab/scan_orders.yaml \
  --report labs/results/orders.json --delay 0.05

# Parameter discovery
accessprobe discover --url http://127.0.0.1:8765/ --cookie 'session=alice'
```

### Manual Verification (curl)

```bash
# Confirm real IDOR
curl -s -H 'Cookie: session=alice' 'http://127.0.0.1:8765/vuln/profile?user_id=2'

# Confirm correct ACL
curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: session=alice' \
  'http://127.0.0.1:8765/secure/profile?user_id=2'
```

### Success Criteria

| Scenario                        | Expected Result                     |
|---------------------------------|-------------------------------------|
| Horizontal IDOR (vuln)          | High confidence true positives      |
| Secure horizontal               | No false positives on foreign IDs   |
| Orders endpoint                 | All horizontal mutations flagged    |
| Discovery                       | Finds `user_id`, `order_id`, etc.   |

---

## 5. Phase 3 — Accuracy Analysis

After each scan, classify every finding:

| Classification | Meaning                                      |
|----------------|----------------------------------------------|
| **TP**         | Real IDOR correctly detected                 |
| **FP**         | Legitimate access incorrectly flagged        |
| **TN**         | Correctly not flagged                        |
| **FN**         | Real IDOR missed                             |

### Focus Areas

1. Horizontal IDOR accuracy (same role, different object IDs)
2. Cross-role noise (self-access and intended admin access)
3. Confidence score reliability
4. Noise from bad candidate values

### Document Results In

- `docs/TEST_RESULTS.md`

---

## 6. Phase 4 — Real Vulnerable Labs (Next Priority)

### Recommended Targets

| Lab                        | What to Test                              | Priority |
|---------------------------|-------------------------------------------|----------|
| **DVWA**                  | IDOR in User Info / SQL Injection pages   | High     |
| **OWASP Juice Shop**      | Basket IDOR, user data, order access      | High     |
| **PortSwigger Web Academy** | Access Control + IDOR labs              | High     |
| **bWAPP**                 | Multiple IDOR challenges                  | Medium   |
| Custom local apps         | Controlled edge cases                     | Medium   |

### Testing Protocol for Each Lab

1. Create a dedicated config file under `labs/<lab_name>/`
2. Export cookies for at least two roles (low privilege + higher privilege)
3. Run scan with `--report` and `--html-report`
4. Manually verify top findings with Burp or curl
5. Record TP / FP / FN in a results table
6. Update `docs/TEST_RESULTS.md`

---

## 7. Phase 5 — Edge Cases & Robustness

### Test Cases to Cover

- [ ] Numeric IDs
- [ ] UUIDs
- [ ] Sequential / patterned IDs
- [ ] Path parameters (`/user/{id}`)
- [ ] JSON body parameters
- [ ] Missing or invalid cookies
- [ ] 403 / 404 / 401 / 500 responses
- [ ] Redirects
- [ ] Very large responses
- [ ] Rate limiting (429)
- [ ] Empty / malformed config files
- [ ] Non-existent parameters
- [ ] High number of candidate values

### Success Criteria

- Tool does not crash
- Clear error messages
- Exit codes are meaningful
- Rate limiting works as expected

---

## 8. Phase 6 — Usability & Reporting

### Checklist

- [ ] CLI help is clear
- [ ] Error messages are actionable
- [ ] JSON report is complete and well-structured
- [ ] HTML report is readable and professional
- [ ] Confidence scores are visible and useful
- [ ] Config file with `cookie_file` works reliably
- [ ] Multi-parameter scanning works correctly

---

## 9. Phase 7 — Advanced Features (Future)

These improve accuracy and reduce noise:

- [ ] Ownership map support (`--own-ids` or config)
- [ ] Privileged role handling (`--privileged-roles`)
- [ ] Better candidate filtering (exclude field names)
- [ ] Minimum confidence threshold (`--min-confidence`)
- [ ] Horizontal-only mode improvements
- [ ] JWT / Bearer token support
- [ ] CSRF token handling

---

## 10. How to Document Results

For every significant test run, update or create an entry in `docs/TEST_RESULTS.md` with:

1. Date and version
2. Target description
3. Commands used
4. Summary table (TP / FP / TN / FN)
5. Notable findings
6. Strengths observed
7. Limitations discovered
8. Recommendations

---

## 11. Recommended Execution Order

1. Always run `pytest -q` first
2. Re-run the local lab suite and confirm results still match `docs/TEST_RESULTS.md`
3. Move to real labs (start with DVWA or Juice Shop)
4. Document accuracy carefully
5. Fix high-impact false positives (ownership / privileged roles)
6. Expand edge-case coverage

---

## 12. Authorization Rule

**Only test systems you own or have explicit written permission to test.**

All laboratory testing must stay on `127.0.0.1` or authorized targets.

---

## 13. Quick Reference Commands

```bash
# Unit tests
pytest -q

# Start local lab
python labs/idor_lab/server.py 8765

# Core local scans
accessprobe scan --config labs/idor_lab/scan_vuln.yaml --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml --report labs/results/secure.json
accessprobe scan --config labs/idor_lab/scan_orders.yaml --report labs/results/orders.json

# Discovery
accessprobe discover --url http://127.0.0.1:8765/ --cookie 'session=alice'
```

---

**End of Test Plan**
