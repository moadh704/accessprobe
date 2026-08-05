# AccessProbe

**Multi-role IDOR & broken access control scanner for authorized web testing.**

AccessProbe finds object-level authorization flaws with horizontal IDOR checks, cross-role tests, confidence scoring, and professional JSON/HTML reports — validated on a local multi-user lab and OWASP Juice Shop.

[![Version](https://img.shields.io/badge/version-0.4.0-cyan)](https://github.com/moadh704/accessprobe)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-33%20passed-brightgreen)](https://github.com/moadh704/accessprobe)
[![License](https://img.shields.io/badge/license-Proprietary-lightgrey)](LICENSE)

<p align="center">
  <img src="docs/assets/banner.jpg" alt="AccessProbe — IDOR and broken access control testing" width="920" />
</p>

---

### Why it exists

Most scanners are noisy on authorization bugs. AccessProbe is built for **one job**: multi-session object ID testing with enough context (ownership map + privileged roles) to cut self-access and intended-admin false positives.

### Proof (v0.4.0)

| Check | Result |
|-------|--------|
| Unit / integration tests | **33/33 passed** |
| Broken lab profile (horizontal IDOR) | Detected — confidence **1.00** |
| Correct lab ACL (secure profile) | **0 false positives** (with ownership + privileged roles) |
| OWASP Juice Shop basket path IDOR | Detected — confidence **1.00** |
| Reports | JSON + HTML |

<p align="center">
  <img src="docs/assets/accuracy-before-after.png" alt="Before/after accuracy: secure ACL false positives drop from 3 to 0" width="900" />
</p>

<p align="center"><em>v0.4 accuracy upgrade — secure endpoint: 3 FPs → 0 FPs</em></p>

<p align="center">
  <img src="docs/assets/report-vuln.png" alt="HTML report for vulnerable IDOR lab scan" width="900" />
</p>

<p align="center"><em>HTML report — vulnerable profile scan (authorized local lab)</em></p>

Full write-up with ground truth and TP/FP tables → **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**  
Step-by-step program → **[docs/TEST_PLAN.md](docs/TEST_PLAN.md)**  
Short accuracy demo clip → **[docs/assets/demo-accuracy.mp4](docs/assets/demo-accuracy.mp4)**

---

## Features

- **Horizontal IDOR** — same role, alternate object IDs  
- **Cross-role** broken access control tests  
- **Ownership map** (`own_ids` / `--own-ids`) — suppress self-access FPs  
- **Privileged roles** (`privileged_roles` / `--privileged-roles`) — suppress intended admin access  
- Confidence-based detection with `--min-confidence`  
- Parameter discovery from URL, HTML, JS, JSON  
- Query, path, body, header, cookie parameter locations  
- Cookie files + raw cookies + **Bearer JWT headers**  
- Rate limiting (`--delay`) · JSON & HTML reports  

---

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
pip install -e ".[dev]"   # pytest, etc.
```

---

## Quick start

### 1. Sessions (cookies)

```bash
mkdir -p cookies
# Export with a browser extension (e.g. Get cookies.txt LOCALLY)
# cookies/user.txt  cookies/admin.txt
```

### 2. Config

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit URL, roles, own_ids, privileged_roles
```

### 3. Scan

```bash
accessprobe scan --config my_scan.yaml \
  --report results.json --html-report report.html
```

### CLI without config

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id --value 1 \
  --original-role user --test-roles admin \
  --cookie "session=YOUR_SESSION" \
  --own-ids "user=1;admin=99" \
  --privileged-roles admin \
  --report out.json
```

### Path parameters (important)

Use a `{name}` placeholder in the URL:

```bash
accessprobe scan \
  --url "http://127.0.0.1:3000/rest/basket/{id}" \
  --param id --value 8 --location path \
  --original-role alice --test-roles bob
```

### Discover parameters

```bash
accessprobe discover --url "https://target.example.com/profile?user_id=1" --cookie "session=..."
accessprobe scan --config my_scan.yaml --discover
```

---

## Accuracy context (v0.4)

```yaml
scan:
  own_ids:
    alice: ["1"]
    bob: ["2"]
  privileged_roles:
    - admin
```

| Setting | Effect |
|---------|--------|
| `own_ids` | If role accesses an ID they own → **not** reported as IDOR |
| `privileged_roles` | Intended broad access for that role is **suppressed** |
| Without them | Tool still works; expect more leads to triage manually |

CLI equivalents: `--own-ids alice=1;bob=2` and `--privileged-roles admin`.

---

## Useful flags

| Flag | Description |
|------|-------------|
| `--min-confidence 0.55` | Minimum confidence to mark vulnerable |
| `--delay 0.25` | Seconds between requests |
| `--no-horizontal` | Skip same-role alternate-ID tests |
| `--own-ids` | Ownership map (reduce self-access FPs) |
| `--privileged-roles` | Roles with intended broad access |
| `--location query\|path\|body\|header\|cookie` | Parameter placement |
| `--discover` | Auto-discover parameters |

---

## Local labs

### Built-in multi-user IDOR lab

```bash
python labs/idor_lab/server.py 8765

accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/v0.4/vuln.json --html-report labs/results/v0.4/vuln.html

accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/v0.4/secure.json
# → expect 0 vulnerable findings with ownership + privileged roles
```

### OWASP Juice Shop (local)

```bash
# Juice Shop on 127.0.0.1:3000
python labs/juice_shop/setup_and_scan.py
```

See [`labs/juice_shop/README.md`](labs/juice_shop/README.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
# expected: 33 passed
```

---

## Project structure

```text
accessprobe/          # scanner package
docs/
  TEST_PLAN.md        # validation program
  TEST_RESULTS.md     # portfolio-ready report
  assets/             # screenshots for README
labs/idor_lab/        # multi-user local target
labs/juice_shop/      # Juice Shop helper (no secrets committed)
labs/results/         # scan artifacts
tests/                # unit + integration tests
```

---

## Disclaimer

**Authorized security testing and education only.**  
Only use AccessProbe on systems you own or have explicit permission to test. All validation in this repository was performed on `127.0.0.1`.
