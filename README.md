# Orange TrustSkill v2.0 🍊

Advanced Security Scanner for OpenClaw Skills

[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](https://github.com/iamoldorange666/orange-trustskill)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## ✨ Features

- 🔍 **Multi-layer Analysis**: Regex + AST + Deep Inspection
- 🎯 **Accurate Detection**: Context-aware pattern matching
- 🌈 **Rich Output**: Colored text, JSON, Markdown formats
- 📊 **Progress Tracking**: Real-time scan progress
- 🔒 **Comprehensive Checks**:
  - Command injection (eval, exec, os.system)
  - Data exfiltration (HTTP requests)
  - Credential theft (SSH keys, passwords, API keys)
  - Sensitive file access (Memory files, configs)
  - File system risks (dangerous deletions)
  - Code obfuscation (Base64, ROT13)

## 🚀 Quick Start

```bash
# Scan a skill
python3 src/cli.py /path/to/skill

# Deep scan with all checks
python3 src/cli.py /path/to/skill --mode deep

# JSON output
python3 src/cli.py /path/to/skill --format json

# Export for LLM review
python3 src/cli.py /path/to/skill --export-for-llm
```

## 📦 Installation

```bash
git clone https://github.com/iamoldorange666/orange-trustskill.git
cd orange-trustskill
```

No dependencies required! Pure Python standard library.

## 🔧 Usage

### Analysis Modes

| Mode | Description | Speed | Accuracy |
|------|-------------|-------|----------|
| `fast` | Regex only | ⚡ Fast | ⭐⭐ |
| `standard` | Regex + AST | ⚡ Balanced | ⭐⭐⭐⭐ |
| `deep` | Full analysis | 🐢 Thorough | ⭐⭐⭐⭐⭐ |

### Output Formats

- **text**: Colored terminal output (default)
- **json**: Machine-readable JSON
- **markdown**: For LLM review

### Examples

```bash
# Basic scan
python3 src/cli.py ~/.openclaw/skills/my-skill

# Deep scan with progress
python3 src/cli.py ~/.openclaw/skills/my-skill --mode deep

# JSON output for CI/CD
python3 src/cli.py ~/.openclaw/skills/my-skill --format json --quiet

# Markdown for manual review
python3 src/cli.py ~/.openclaw/skills/my-skill --export-for-llm > report.md
```

## 🛡️ Security Checks

### HIGH Risk
- Command injection (eval, exec, os.system with variables)
- Data exfiltration (HTTP POST, suspicious URLs)
- File deletion (rm -rf, shutil.rmtree)
- Credential access (.ssh/, passwords, tokens)
- Sensitive file access (MEMORY.md, config.json)

### MEDIUM Risk
- Network requests (requests, urllib)
- File access outside workspace (/etc/, ~)
- Code obfuscation (Base64, ROT13)
- Dynamic imports (__import__, importlib)
- API key usage

### LOW Risk
- Shell commands (static commands)
- File operations (open, path manipulation)

## 🏗️ Architecture

```
src/
├── __init__.py              # Package init
├── types.py                 # Data types (Severity, ScanResult, etc.)
├── rules.py                 # Security patterns and rules
├── scanner.py               # Main scanner logic
├── cli.py                   # Command line interface
├── analyzers/
│   ├── base.py              # Analyzer base class
│   ├── regex_analyzer.py    # Regex pattern matching
│   └── ast_analyzer.py      # Python AST analysis
└── formatters/
    ├── base.py              # Formatter base class
    ├── text_formatter.py    # Colored text output
    ├── json_formatter.py    # JSON output
    └── markdown_formatter.py # Markdown output
```

## 🔍 How It Works

1. **File Discovery**: Recursively find all relevant files
2. **Multi-layer Analysis**:
   - Regex: Fast pattern matching
   - AST: Deep code structure analysis (Python only)
3. **Context-aware Filtering**: Reduce false positives
4. **Risk Assessment**: Categorize and prioritize findings
5. **Rich Reporting**: Multiple output formats

## 🆚 Comparison with v1.x

| Feature | v1.x | v2.0 |
|---------|------|------|
| Regex Analysis | ✅ | ✅ |
| AST Analysis | ❌ | ✅ |
| Multi-format Output | ❌ | ✅ |
| Progress Tracking | ❌ | ✅ |
| Colored Output | ❌ | ✅ |
| Confidence Scoring | ❌ | ✅ |
| Modular Architecture | ❌ | ✅ |

## 🤝 Contributing

Contributions welcome! Please ensure:
- Code follows PEP 8
- Add tests for new features
- Update documentation

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🙏 Acknowledgments

Inspired by [TrustSkill](https://github.com/nonabit/TrustSkill) but optimized for OpenClaw with specific focus on:
- OpenClaw memory file protection
- API key usage detection
- Safe service whitelisting

---

Made with 🧡 by Orange
