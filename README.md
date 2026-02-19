# Orange's TrustSkill - Skill Security Scanner

安全扫描工具，用于检测 OpenClaw skills 中的潜在恶意代码、后门和安全风险。
- ✅ 命令注入检测（eval, exec, os.system 等）
- ✅ 数据外泄检测（可疑 HTTP 请求）
- ✅ 文件系统风险（危险删除操作）
- ✅ 敏感信息保护（密钥/凭证访问）
- ✅ 代码混淆检测（base64, rot13 等）

## 安装

1. 确保 skill 文件夹在正确位置：
```
/path/to/skills/orange-trustskill/
├── SKILL.md
├── references/
│   └── security_patterns.md
└── scripts/
    └── scan_skill.py
```

2. 给脚本添加执行权限：
```bash
chmod +x /path/to/skills/orange-trustskill/scripts/scan_skill.py
```

## 使用方法

### 基本扫描
```bash
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skill-folder
```

### 深度扫描（包含低风险提示）
```bash
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skill-folder --mode deep
```

### JSON 格式输出
```bash
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skill-folder --format json
```

### 导出给 LLM 审查
```bash
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skill-folder --export-for-llm
```

## 扫描模式

| 模式 | 说明 |
|------|------|
| **fast** | 仅正则匹配（最快） |
| **standard** | 正则 + 示例排除（推荐） |
| **deep** | 正则 + 示例排除 + 低风险检测（最全面） |

## 风险等级

- 🔴 **HIGH**: 高风险，必须人工审查（eval, 数据外泄, 系统文件删除等）
- 🟡 **MEDIUM**: 中风险，建议审查（网络请求, 文件操作等）
- 🟢 **LOW**: 低风险，了解即可（静态 shell 命令等）

## 示例

```bash
# 扫描安装的 skill
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skills/some-new-skill

# 扫描官方 skill（OpenClaw 安装路径示例）
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /opt/homebrew/lib/node_modules/openclaw/skills/nano-pdf --mode deep

# 检查前输出 JSON 供程序处理
python3 /path/to/skills/orange-trustskill/scripts/scan_skill.py /path/to/skill --format json --quiet
```

## 安全建议

1. **安装新 skill 前必扫描** - 特别是来自非官方渠道的 skill
2. **定期审计** - 对重要 skills 定期重新扫描
3. **关注 HIGH 风险** - 出现 HIGH 风险时必须人工确认
4. **不要完全依赖自动化** - 这是辅助工具，最终判断需要人
