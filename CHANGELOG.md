# Orange TrustSkill Changelog

## [2.3.0] - 2026-02-22

### ✨ New Features
- **SECURITY.md Compliance Checker**
  - New script: `check_security_compliance.py`
  - Checks if Agents properly reference SECURITY.md
  - Validates security baseline principles
  - Scores compliance (0-100)
  - Supports checking all agents or specific SOUL.md files

### 🔧 Improvements
- Enhanced security detection patterns
- Better reporting for compliance issues

### 📝 Usage
```bash
# Check all agents' SECURITY.md compliance
python scripts/check_security_compliance.py

# Check specific agent
python scripts/check_security_compliance.py /path/to/SOUL.md
```

## [2.2.0] - 2025-02-20

### ✨ New Features
- 新增多重安全防护
- 增强隐私文件检测
- 改进风险评级算法

## [2.1.0] - 2025-02-18

### ✨ New Features
- 新增记忆文件保护功能
- 支持检测 MEMORY.md / SOUL.md 访问

## [2.0.0] - 2025-02-15

### ✨ New Features
- Complete rewrite with AST analysis
- Advanced pattern matching
- Comprehensive risk detection

## [1.0.0] - 2025-02-10

### 🎉 Initial Release
- Basic skill security scanning
- Pattern-based detection
- Risk level classification
