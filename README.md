# AccessProbe

**A specialized tool for detecting IDOR and Broken Access Control vulnerabilities.**

AccessProbe helps security researchers and red teamers find authorization issues through intelligent multi-role testing, horizontal IDOR checks, and professional reporting.

## Features

- Multi-parameter scanning via YAML configuration
- **Horizontal IDOR** tests (same role, alternate object IDs)
- **Cross-role** broken access control tests
- Automatic extraction of potential IDs from responses
- Confidence-based detection with tunable threshold
- Parameter discovery from URL, HTML, JS, and JSON APIs
- Professional JSON and HTML reports
- YAML configuration with `cookie_file` support (paths relative to the config file)
- Query, path, body, header, and cookie parameter locations
- Built-in rate limiting (`--delay`)
- Clean CLI (`scan` + `discover`)

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
# optional dev tools
pip install -e ".[dev]"
```

## Quick Start

### 1. Create cookies directory and export cookies

```bash
mkdir -p cookies
# Export cookies using a browser extension (e.g. Get cookies.txt LOCALLY)
# Save as cookies/user.txt and cookies/admin.txt
```

### 2. Create config file

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit my_scan.yaml
```

### 3. Run the scan

```bash
accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
```

### CLI without config

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id --value 1 \
  --original-role user --test-roles admin \
  --cookie "session=YOUR_SESSION" \
  --report out.json
```

### Discover parameters

```bash
accessprobe discover --url "https://target.example.com/profile?user_id=1" --cookie "session=..."
# or auto-discover during scan:
accessprobe scan --config my_scan.yaml --discover
```

## Configuration

**Option A: cookie_file (recommended)**

```yaml
sessions:
  - name: user
    cookie_file: cookies/user.txt   # relative to the config file directory
```

**Option B: raw cookies**

```yaml
sessions:
  - name: user
    cookies:
      session: "your_cookie_value"
```

See `examples/example_config.yaml` for a full example.

### Useful flags

| Flag | Description |
|------|-------------|
| `--min-confidence 0.55` | Minimum confidence to mark vulnerable |
| `--delay 0.25` | Seconds between requests |
| `--no-horizontal` | Skip same-role alternate-ID tests |
| `--location query\|path\|body\|header\|cookie` | Parameter placement |
| `--method GET` | HTTP method |
| `--discover` | Auto-discover parameters from target |

## Development

```bash
pip install -e ".[dev]"
pytest -q
# expected: 28 passed
```

## Validation & labs

AccessProbe ships a full testing program designed for reproducible, authorized demos:

| Document | Purpose |
|----------|---------|
| **[docs/TEST_PLAN.md](docs/TEST_PLAN.md)** | Step-by-step validation plan (unit → lab → real app → edges) |
| **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)** | Portfolio-ready report: ground truth, TP/FP analysis, Juice Shop results |

### Built-in multi-user IDOR lab

```bash
python labs/idor_lab/server.py 8765
accessprobe scan --config labs/idor_lab/scan_vuln.yaml \
  --report labs/results/vuln.json --html-report labs/results/vuln.html
accessprobe scan --config labs/idor_lab/scan_secure.yaml \
  --report labs/results/secure.json
```

### OWASP Juice Shop (local)

If you run Juice Shop on `127.0.0.1:3000`:

```bash
python labs/juice_shop/setup_and_scan.py
```

See [`labs/juice_shop/README.md`](labs/juice_shop/README.md). Horizontal basket IDOR is the demonstrated path (`GET /rest/basket/{id}` with Bearer JWT).

### Headline validation results (v0.3.0)

| Check | Result |
|-------|--------|
| Unit tests | **28/28 passed** |
| Horizontal IDOR on broken lab ACL | High-confidence **true positives** |
| Foreign IDs on correct lab ACL | **Not flagged** (true negatives) |
| Juice Shop basket path IDOR | Detected (confidence **1.00**) |
| Cross-role / self-access | Manual triage still required |

## Disclaimer

This tool is for **authorized security testing and educational purposes only**.
Only use it on systems you own or have explicit permission to test.
