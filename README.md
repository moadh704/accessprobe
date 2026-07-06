# AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool** — v0.2+

AccessProbe is a specialized, modular tool for discovering and validating **IDOR** and **Broken Access Control** vulnerabilities with good accuracy and usability.

## Current Strengths (v0.2+)

- **Improved Detection** — Confidence scoring + multiple detection signals
- **Multi-parameter scanning** — Test many parameters in one run via config
- **Smart value generation** — Especially strong on numeric IDs
- **Professional Reporting** — Clean JSON + modern HTML reports
- **Configuration driven** — Full YAML support for sessions and scans
- **Rate limiting** — Basic politeness to avoid detection
- **Clean Architecture** — Easy to extend and maintain

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### 1. Using Config (Recommended)

```bash
# Edit examples/example_config.yaml with your cookies
accessprobe scan --config examples/example_config.yaml --report results.json
```

### 2. Single Parameter (Manual)

```bash
accessprobe scan \
  --url "https://target.com/profile" \
  --param user_id \
  --value 42 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_cookie_here"
```

## Key Features

- Multi-role testing
- Automatic candidate value generation
- Confidence-based detection
- Beautiful HTML + JSON reports
- YAML configuration
- Basic rate limiting

## Architecture

```
Discovery → Session Management → Testing Engine → Detection → Reporting
```

## Current Status

**Rating: ~8.5/10** for a specialized IDOR tool.

It is now a strong, usable tool for authorized testing and red team work, with good accuracy and modern features.

## Disclaimer

For authorized security testing and educational purposes only.
