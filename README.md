# AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool**

AccessProbe is a specialized tool for discovering and validating **Insecure Direct Object References (IDOR)** and other **Broken Access Control** vulnerabilities in web applications.

It is designed for red teamers, bug bounty hunters, and web application security testers who need more precise testing than general vulnerability scanners provide.

## Features

- Multi-role / multi-user session testing
- Intelligent parameter discovery (URL, HTML forms, links, basic JavaScript)
- Multiple detection methods (status codes, similarity, content differences)
- Professional JSON and HTML reporting
- Clean, modular, and extensible architecture
- Async support using `httpx`

## Installation

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

After installation, you can use the CLI:

```bash
accessprobe --help
accessprobe scan --help
```

## Quick Start

See the [examples/basic_idor_test.py](examples/basic_idor_test.py) for a complete working example.

Basic usage with Python:

```python
from accessprobe import SessionManager, UserSession, Parameter, ParameterLocation, IDORTester

import asyncio

async def main():
    session = UserSession(name="user", cookies={"session": "your_cookie"})
    manager = SessionManager()
    manager.add_session(session)

    param = Parameter(name="id", location=ParameterLocation.QUERY, value=123)
    tester = IDORTester(manager)

    result = await tester.test_parameter(
        parameter=param,
        target_url="https://target.example.com/profile",
        original_session="user",
        test_sessions=["admin"],
    )
    print(result)

asyncio.run(main())
```

## Project Structure

```
accessprobe/
├── accessprobe/
│   ├── __init__.py
│   ├── models.py          # Core data models
│   ├── session.py         # Multi-role session management
│   ├── tester.py          # IDOR testing engine
│   ├── detector.py        # Response comparison & detection
│   ├── discovery.py       # Parameter discovery from HTML/URL/JS
│   ├── reporter.py        # JSON & HTML reporting
│   └── cli.py             # Command line interface
├── examples/
├── reports/             # Generated reports
└── README.md
```

## Architecture

AccessProbe follows a clean modular design:

1. **Discovery** → Find potential IDOR parameters
2. **Session Management** → Handle multiple user roles
3. **Testing Engine** → Test parameters across roles
4. **Detection** → Analyze responses for authorization issues
5. **Reporting** → Generate professional reports

## CLI Usage

```bash
# Show help
accessprobe --help

# Run a scan (structure ready, full functionality coming soon)
accessprobe scan --url https://target.com/profile --param user_id --value 42
```

## Roadmap

- [ ] Full session management from CLI / config file
- [ ] Improved discovery (more sources + smarter filtering)
- [ ] Better value swapping logic
- [ ] Integration with WebVulnScanner
- [ ] More advanced detection techniques

## Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT License

---

Built as part of a red team tooling portfolio by [@moadh704](https://github.com/moadh704).