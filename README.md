# AccessProbe

<p>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-Red%20Team-ED4646?style=flat-square&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/CLI-Tool-00C853?style=flat-square&logo=terminal&logoColor=white" />
  <img src="https://img.shields.io/badge/IDOR-Detection-FF6B6B?style=flat-square&logo=bug&logoColor=white" />
  <img src="https://img.shields.io/badge/Config-YAML-FFCA28?style=flat-square&logo=yaml&logoColor=black" />
</p>

**A specialized tool for detecting IDOR and Broken Access Control vulnerabilities in web applications.**

AccessProbe helps security researchers and red teamers find authorization issues through intelligent multi-role testing and professional reporting.

## Features

- Multi-parameter scanning via YAML configuration
- Automatic extraction of potential IDs from responses
- Confidence-based detection with multiple signals
- Professional JSON and modern HTML reports
- Built-in rate limiting
- Clean CLI with rich output

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

## Quick Start

### Using Configuration (Recommended)

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit cookies in my_scan.yaml

accessprobe scan --config my_scan.yaml --report results.json --html-report report.html
```

### Manual Mode

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

1. Load sessions/roles
2. Extract candidate values from responses
3. Test parameters across different privilege levels
4. Analyze responses using multiple signals
5. Generate professional reports

## Current Status

AccessProbe is a focused tool for IDOR testing. It provides good accuracy through confidence scoring and smart value handling. Manual verification of results is recommended.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**.
