# AccessProbe

**A specialized tool for detecting IDOR and Broken Access Control vulnerabilities.**

AccessProbe helps security researchers find authorization issues in web applications using multi-role testing, intelligent value extraction, and professional reporting.

## Features

- Multi-parameter scanning via configuration
- Automatic extraction of potential IDs from responses
- Confidence scoring with multiple detection signals
- Professional JSON and HTML reports
- YAML configuration for sessions and scan targets
- Built-in rate limiting
- Clean CLI with rich formatted output

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### Using Configuration File (Recommended)

```bash
cp examples/example_config.yaml my_scan.yaml
# Add your cookies in my_scan.yaml

accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
```

### Manual Single-Parameter Scan

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id \
  --value 42 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_cookie"
```

## How It Works

1. Load sessions and roles
2. Extract candidate values (including from previous responses)
3. Test parameters across different roles
4. Analyze responses using multiple detection signals
5. Generate reports

## Current Status

AccessProbe is a focused tool for IDOR testing. It offers good accuracy through confidence-based detection and smart value handling. Manual verification of results is recommended.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**.
