# AccessProbe Test Results

**Date:** 2026-08-05  
**Version:** 0.3.0  
**Scope:** Local authorized IDOR lab only

---

## Quick Summary

| Capability                     | Result                                      |
|--------------------------------|---------------------------------------------|
| Unit tests                     | 28/28 passed                                |
| Horizontal IDOR detection      | Strong (confirmed true positives)           |
| Correct ACL (403 responses)    | Strong (no horizontal false positives)      |
| Cross-role testing             | Noisy — flags self-access and intended admin |
| Parameter discovery            | Pass                                        |
| Config / cookie files / reports| Pass                                        |

Horizontal IDOR works well. Cross-role findings need manual triage.

---

## What was tested

Local multi-user lab (`labs/idor_lab/`):

| Endpoint                        | Expected behavior                     |
|---------------------------------|---------------------------------------|
| `/vuln/profile?user_id=N`       | Broken ACL (any user can read any)    |
| `/secure/profile?user_id=N`     | Correct ACL (own + admin only)        |
| `/orders?order_id=N`            | Broken object authorization           |

Sessions: `alice` (user 1), `bob` (user 2), `admin` (user 3).

Ground truth verified with curl before scanning.

---

## Key Results

### Vulnerable target (`scan_vuln.yaml`)

| Finding                              | Conf. | Classification     |
|--------------------------------------|-------|--------------------|
| alice → user_id=2 (horizontal)       | 1.00  | TP                 |
| bob → user_id=1 (cross-role)         | 0.72  | TP                 |
| bob → user_id=2 (own profile)        | 0.96  | FP (self-access)   |
| admin → alternate IDs                | 0.96  | TP                 |
| Non-existent / garbage IDs           | 0.00  | TN                 |

### Secure target (`scan_secure.yaml`)

| Finding                              | Conf. | Classification              |
|--------------------------------------|-------|-----------------------------|
| alice → user_id=2 (horizontal)       | —     | TN (correctly not flagged)  |
| bob → user_id=1                      | —     | TN                          |
| bob → user_id=2 (own profile)        | 0.96  | FP (self-access)            |
| admin → user_id=1/2                  | 0.72–0.96 | FP (no privilege model) |

### Orders (`scan_orders.yaml`)

All horizontal mutations returned 200 → correctly flagged (TP).

### Discovery

4 parameters found from lab homepage (`user_id`, `account_id`, `order_id`, `id`).

---

## Known Limitations

- No ownership model → self-access is flagged as vulnerable
- No privileged-role handling → intended admin access is flagged
- Candidate extraction can produce noise values (usually true negatives)
- Only simple cookie auth was tested

---

## How to re-run

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

Artifacts are under `labs/results/`.

All testing was performed against a local lab on `127.0.0.1`. No external systems were scanned.
