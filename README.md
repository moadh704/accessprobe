# AccessProbe

**Specialized tool for detecting IDOR and Broken Access Control vulnerabilities in web applications.**

AccessProbe helps security researchers and red teamers find authorization issues through intelligent multi-role testing, automatic value extraction, and professional reporting.

## Features

- Multi-parameter scanning from configuration
- Automatic extraction of potential IDs from HTTP responses
- Confidence-based detection using multiple signals
- Professional JSON and modern HTML reports
- YAML configuration support for sessions and targets
- Built-in rate limiting
- Clean command-line interface with rich output

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### Recommended: Using a Configuration File

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit my_scan.yaml with your session cookies

accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
```

### Manual Mode (Single Parameter)

```bash
accessprobe scan \
  --url "https://target.example.com/profile" \
  --param user_id \
  --value 42 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_cookie_value"
```

## How It Works

1. Load user sessions and roles
2. Extract candidate values from responses when possible
3. Test parameters across different privilege levels
4. Analyze responses using multiple detection techniques
5. Generate professional reports

## Current Status

AccessProbe is a focused tool for IDOR testing. It provides good detection capabilities through confidence scoring and smart value handling. Results should always be manually verified.

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.

Unauthorized access to systems is illegal.
