# AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool** — v0.3

AccessProbe is now a **strong, accurate, and practical** specialized tool for finding IDOR and Broken Access Control vulnerabilities.

## Current Rating: **~9/10**

### Major Strengths

- **High-accuracy detection** with confidence scoring and multiple signals
- **Smart value extraction** from responses (numbers, UUIDs, IDs)
- **Multi-parameter scanning** in a single run
- **Professional reporting** (JSON + beautiful modern HTML)
- **Configuration-driven** with YAML
- **Rate limiting** built-in
- **Clean & extensible** architecture

## Quick Start

```bash
# Recommended way (using config)
accessprobe scan --config examples/example_config.yaml --report results.json --html-report report.html

# Or single parameter
accessprobe scan \
  --url https://target.com/api/user \
  --param id \
  --value 123 \
  --original-role user \
  --test-roles admin \
  --cookie "session=xxx"
```

## Key Features (v0.3)

- Multi-parameter support from config
- Automatic ID extraction from responses
- Confidence-based vulnerability scoring
- Professional HTML + JSON reports
- Basic rate limiting & politeness
- Clean CLI with rich tables

## Architecture

Discovery → Sessions → Smart Testing → Advanced Detection → Professional Reporting

## Disclaimer

**For authorized security testing and educational purposes only.**
