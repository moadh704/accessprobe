# AccessProbe

**A specialized tool for detecting IDOR and Broken Access Control vulnerabilities.**

AccessProbe helps security researchers and red teamers find authorization issues through intelligent multi-role testing and professional reporting.

## Features

- Multi-parameter scanning via YAML configuration
- Automatic extraction of potential IDs from responses
- Confidence-based detection
- Professional JSON and HTML reports
- YAML configuration with `cookie_file` support
- Built-in rate limiting
- Clean CLI

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### 1. Create cookies directory and export cookies

```bash
mkdir -p cookies
# Export cookies using browser extension (Get cookies.txt LOCALLY)
# Save as cookies/user.txt and cookies/admin.txt
```

### 2. Create config file

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit my_scan.yaml (it uses cookie_file by default)
```

### 3. Run the scan

```bash
accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
```

## Configuration

You can define sessions using either:

**Option A: cookie_file (Recommended)**

```yaml
sessions:
  - name: user
    cookie_file: cookies/user.txt
```

**Option B: Raw cookies**

```yaml
sessions:
  - name: user
    cookies:
      session: "your_cookie_value"
```

See `examples/example_config.yaml` for a full example.

## Current Status

AccessProbe is a focused tool for IDOR testing. It provides good accuracy and is practical for authorized assessments.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**.
