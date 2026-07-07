# AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool**

AccessProbe is a specialized, high-accuracy tool designed for red teamers and security researchers to discover and validate **Insecure Direct Object References (IDOR)** and **Broken Access Control** vulnerabilities.

![AccessProbe](https://img.shields.io/badge/AccessProbe-v0.2-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## Overview

AccessProbe stands out with its **focused approach** on authorization vulnerabilities. Unlike general scanners, it provides:

- High-accuracy detection with confidence scoring
- Smart value extraction from responses
- Multi-parameter testing support
- Professional reporting
- Clean configuration-driven workflow

---

## Key Features

| Feature                    | Description                                      |\n|----------------------------|--------------------------------------------------|
| **Advanced Detection**     | Confidence scoring + multiple detection signals  |
| **Smart Value Generation** | Extracts potential IDs from responses            |
| **Multi-Parameter Scans**  | Test many parameters in a single run             |
| **Professional Reports**   | Clean JSON + modern HTML reports                 |
| **Configuration System**   | Full YAML support for sessions and targets       |
| **Rate Limiting**          | Built-in politeness to avoid detection           |

---

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

---

## Usage

### Recommended: Using Configuration File

```bash
accessprobe scan --config examples/example_config.yaml --report results.json
```

### Manual Single Parameter

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id \
  --value 42 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_session_cookie"
```

---

## Example Output

```text
ACCESS PROBE  v0.2
Advanced IDOR & Broken Access Control Testing

Scan Started
Target:     https://target.example.com/profile
Parameters: 3
Roles:      user → admin

Parameter: user_id • query
Test Role │ Value │ Vulnerable │ Confidence │ Severity
admin     │ 43    │ ✗ Vulnerable │ 0.93       │ HIGH
admin     │ 41    │ ✓ Safe       │ 0.12       │ LOW

Scan Complete • 2 vulnerable out of 12 tests
Report saved to results.json
```

---

## Project Structure

```
accessprobe/
├── accessprobe/
│   ├── cli.py          # Professional command line interface
│   ├── tester.py       # Core testing engine + smart value extraction
│   ├── detector.py     # High-accuracy detection with confidence
│   ├── reporter.py     # Professional JSON + HTML reporting
│   ├── config.py       # YAML configuration system
│   ├── discovery.py    # Parameter discovery
│   ├── session.py      # Multi-role session management
│   └── models.py       # Core data models
├── examples/
└── README.md
```

---

## Current Status

**AccessProbe v0.2** is a strong, production-ready specialized tool for authorized IDOR testing.

It features high detection accuracy, excellent usability, and professional reporting.

---

## Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Unauthorized use against systems you do not have explicit permission to test is illegal.

---

## License

MIT License

---

**Built with precision by moadh704**
