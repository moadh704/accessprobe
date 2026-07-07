# 🔍 AccessProbe

**Advanced IDOR & Broken Access Control Testing Tool**

A focused, modern tool for discovering authorization vulnerabilities in web applications through intelligent multi-role testing.

---

## ✨ Features

| Feature                        | Description                                      |
|--------------------------------|--------------------------------------------------|
| **Multi-Parameter Scanning**   | Test many parameters in a single run             |
| **Smart Value Extraction**     | Automatically pulls potential IDs from responses |
| **Confidence-Based Detection** | Multiple signals + scoring for better accuracy   |
| **Professional Reporting**     | Clean JSON + beautiful modern HTML reports       |
| **YAML Configuration**         | Define sessions and targets easily               |
| **Rate Limiting**              | Built-in politeness to avoid detection           |
| **Rich CLI Output**            | Beautiful tables and summaries                   |

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/moadh704/accessprobe.git
cd accessprobe
pip install -e .
```

### 2. Create a Config (Recommended)

```bash
cp examples/example_config.yaml my_scan.yaml
# Edit my_scan.yaml and add your session cookies
```

### 3. Run a Scan

```bash
accessprobe scan \
  --config my_scan.yaml \
  --report results.json \
  --html-report report.html
```

---

## 📄 Usage Examples

**Single Parameter (Manual)**

```bash
accessprobe scan \
  --url "https://target.com/api/user" \
  --param id \
  --value 123 \
  --original-role user \
  --test-roles admin \
  --cookie "session=your_cookie"
```

---

## ⚙️ How It Works

1. Load sessions and roles from config or CLI
2. Extract candidate values (including from previous responses)
3. Test parameters across different privilege levels
4. Analyze responses using multiple detection signals
5. Generate professional JSON + HTML reports

---

## 📊 Current Status

AccessProbe is a specialized tool focused on IDOR detection. It offers good accuracy through confidence scoring and smart value extraction. Like all automated tools, results should be validated manually.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Unauthorized testing is illegal.
