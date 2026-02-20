# Orange TrustSkill v2.2 🍊

OpenClaw Skills 高级安全扫描器

[![版本](https://img.shields.io/badge/version-2.2.0-orange.svg)](https://github.com/iamoldorange666/orange-trustskill)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![协议](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## ✨ 功能特性

- 🔍 **多层分析**: 正则 + AST + 深度检查
- 🎯 **精准检测**: 上下文感知模式匹配
- 🌈 **丰富输出**: 彩色文本、JSON、Markdown 格式
- 📊 **进度跟踪**: 实时扫描进度显示
- 🔒 **全面检查**:
  - 命令注入 (eval, exec, os.system)
  - 数据外泄 (HTTP 请求)
  - 凭证窃取 (SSH 密钥、密码、API Key)
  - 敏感文件访问 (Memory 文件、配置)
  - 文件系统风险 (危险删除)
  - 代码混淆 (Base64, ROT13)

## 🚀 快速开始

```bash
# 扫描 skill
python3 src/cli.py /path/to/skill

# 深度扫描（完整检查）
python3 src/cli.py /path/to/skill --mode deep

# JSON 输出
python3 src/cli.py /path/to/skill --format json

# 导出给 LLM 审查
python3 src/cli.py /path/to/skill --export-for-llm
```

## 📦 安装

```bash
git clone https://github.com/iamoldorange666/orange-trustskill.git
cd orange-trustskill
```

无需额外依赖！纯 Python 标准库实现。

## 🔧 使用方法

### 分析模式

| 模式 | 说明 | 速度 | 准确度 |
|------|------|------|--------|
| `fast` | 仅正则 | ⚡ 快 | ⭐⭐ |
| `standard` | 正则 + AST | ⚡ 均衡 | ⭐⭐⭐⭐ |
| `deep` | 完整分析 | 🐢 彻底 | ⭐⭐⭐⭐⭐ |

### 输出格式

- **text**: 彩色终端输出（默认）
- **json**: 机器可读 JSON
- **markdown**: 用于 LLM 审查

### 示例

```bash
# 基础扫描
python3 src/cli.py ~/.openclaw/skills/my-skill

# 深度扫描（带进度）
python3 src/cli.py ~/.openclaw/skills/my-skill --mode deep

# CI/CD JSON 输出
python3 src/cli.py ~/.openclaw/skills/my-skill --format json --quiet

# Markdown 手动审查
python3 src/cli.py ~/.openclaw/skills/my-skill --export-for-llm > report.md
```

## 🛡️ 安全检查项

### 高风险 🔴
- 命令注入 (eval, exec, 带变量的 os.system)
- 数据外泄 (HTTP POST, 可疑 URL)
- **混淆外泄 (base64 + curl/webhook)** ⭐v2.2
- 文件删除 (rm -rf, shutil.rmtree)
- 凭证访问 (.ssh/, 密码, Token)
- 记忆文件访问 (AGENTS.md, SOUL.md, USER.md, MEMORY.md)
- **Shell 历史访问 (.bash_history, .zsh_history)** ⭐v2.2
- **钥匙串访问 (macOS security)** ⭐v2.2
- **凭证文件访问 (.netrc, .aws, .docker)** ⭐v2.2
- 敏感文件访问 (OpenClaw 配置、Shell 配置)

### 中风险 🟡
- 网络请求 (requests, urllib)
- 工作区外文件访问 (/etc/, ~)
- 代码混淆 (Base64, ROT13)
- 动态导入 (__import__, importlib)
- API Key 使用

### 低风险 🟢
- Shell 命令 (静态命令)
- 文件操作 (open, path 操作)

## 🏗️ 架构

```
src/
├── __init__.py              # 包初始化
├── types.py                 # 数据类型 (Severity, ScanResult 等)
├── rules.py                 # 安全模式和规则
├── scanner.py               # 主扫描器逻辑
├── cli.py                   # 命令行接口
├── analyzers/
│   ├── base.py              # 分析器基类
│   ├── regex_analyzer.py    # 正则模式匹配
│   └── ast_analyzer.py      # Python AST 分析
└── formatters/
    ├── base.py              # 格式化器基类
    ├── text_formatter.py    # 彩色文本输出
    ├── json_formatter.py    # JSON 输出
    └── markdown_formatter.py # Markdown 输出
```

## 🔍 工作原理

1. **文件发现**: 递归查找所有相关文件
2. **多层分析**:
   - 正则: 快速模式匹配
   - AST: 深度代码结构分析 (仅 Python)
3. **上下文感知过滤**: 减少误报
4. **风险评估**: 分类和优先级排序
5. **丰富报告**: 多种输出格式

## 🆚 v1.x 对比

| 功能 | v1.x | v2.0 |
|------|------|------|
| 正则分析 | ✅ | ✅ |
| AST 分析 | ❌ | ✅ |
| 多格式输出 | ❌ | ✅ |
| 进度跟踪 | ❌ | ✅ |
| 彩色输出 | ❌ | ✅ |
| 置信度评分 | ❌ | ✅ |
| 模块化架构 | ❌ | ✅ |

## 🤝 贡献

欢迎贡献！请确保：
- 代码遵循 PEP 8
- 为新功能添加测试
- 更新文档

## 📄 协议

MIT 协议 - 查看 [LICENSE](LICENSE) 文件

---

用 🧡 制作 by Orange
