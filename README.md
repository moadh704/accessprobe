# AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool**

AccessProbe is a specialized web application security tool designed to discover and validate **IDOR (Insecure Direct Object References)** and other **Broken Access Control** vulnerabilities more intelligently than general-purpose scanners.

It is built for red teamers, bug bounty hunters, and web application pentesters who need precise, reliable testing of authorization flaws.

## 🎯 Vision

Most web vulnerability scanners treat IDORs superficially. AccessProbe focuses specifically on this high-impact vulnerability class with:

- Multi-role/session testing
- Smart parameter discovery
- Multiple detection methods
- Clear, actionable reporting

This tool is being developed as part of a red team tooling portfolio alongside [WebVulnScanner](https://github.com/moadh704/webvulnscanner).

## ✨ Key Features (Planned)

### Phase 1 (MVP)
- Multi-user/role session support (cookies & headers)
- Parameter and endpoint discovery
- Core IDOR testing engine
- Status code + response similarity detection
- JSON + HTML reporting
- Clean CLI with rich output

### Phase 2
- Advanced parameter discovery (forms, JS, APIs, path params)
- Improved detection scoring
- Support for various ID formats
- Rate limiting & evasion options
- Configuration file support

### Phase 3+
- Stateful testing (CSRF, tokens)
- Side-effect detection
- Burp/ZAP integration options
- Direct integration with WebVulnScanner

## 🚀 Getting Started

### Prerequisites
- Python 3.10+

### Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -r requirements.txt
```

### Basic Usage (Coming Soon)

```bash
python -m accessprobe --help
```

## 📋 Project Structure

```
accessprobe/
├── accessprobe/
│   ├── cli.py
│   ├── models.py
│   ├── session.py
│   ├── discovery.py
│   ├── tester.py
│   ├── detector.py
│   ├── reporter.py
│   └── utils.py
├── reports/
├── examples/
├── tests/
└── README.md
```

## ⚠️ Disclaimer

**This tool is for authorized security testing and educational purposes only.**

- Only use it on systems you own or have explicit written permission to test.
- Unauthorized access to computer systems is illegal.
- The developers are not responsible for any misuse of this tool.

## 🚧 Roadmap

See the [GitHub Projects](https://github.com/moadh704/accessprobe/projects) or Issues for current progress.

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss major changes.

## 👍 Acknowledgments

Inspired by real-world web red teaming needs and the lack of specialized open-source IDOR testing tools.

---

**Built with ❤️ by moadh704** | Part of the red team tooling journey