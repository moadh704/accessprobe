# AccessProbe

**Specialized tool for detecting IDOR and Broken Access Control vulnerabilities.**

AccessProbe helps security researchers and red teamers find authorization flaws in web applications through multi-role testing, smart value extraction, and professional reporting.

## Features

- Multi-parameter scanning from a single config file
- Automatic extraction of potential IDs from responses
- Confidence-based detection with multiple signals
- Professional JSON and HTML reporting
- YAML-based configuration for sessions and targets
- Built-in rate limiting
- Clean CLI with rich output tables

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### Using a Configuration File (Recommended)

1. Copy the example config:
   ```bash
   cp examples/example_config.yaml my_scan.yaml
   ```
2. Edit `my_scan.yaml` and add your session cookies.
3. Run the scan:
   ```bash
   accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
   ```

### Manual Single Parameter Scan

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id \
  --value 42 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_cookie_value"
```

## Configuration

AccessProbe uses a simple YAML format. See `examples/example_config.yaml` for a full example.

You can define multiple sessions (roles) and multiple parameters to test in one run.

## How It Works

1. Loads sessions/roles from config or CLI
2. Extracts candidate values (including from previous responses)
3. Tests parameters across different privilege levels
4. Analyzes responses using multiple detection signals
5. Generates professional reports

## Current Status

AccessProbe is a focused tool for IDOR testing. It has good detection capabilities and is practical for authorized security assessments. Like any automated tool, it works best when combined with manual verification.

## Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Unauthorized use against systems you do not have explicit permission to test is illegal.
