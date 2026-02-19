# Orange's TrustSkill - Skill Security Scanner

安全扫描工具，用于检测 OpenClaw skills 中的潜在恶意代码、后门、凭证窃取和隐私风险。

## 功能特性

- ✅ **命令注入检测** - eval, exec, os.system 等危险函数
- ✅ **数据外泄检测** - 可疑 HTTP 请求、数据上传
- ✅ **凭证窃取检测** - SSH 密钥、密码、Token、API Key 访问
- ✅ **隐私文件检测** - Memory 文件、配置文件、Shell 配置访问
- ✅ **文件系统风险** - 危险删除操作、越界文件访问
- ✅ **代码混淆检测** - Base64, ROT13 等编码
- ✅ **可疑 URL 检测** - Pastebin、IP 直连等

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
| **standard** | 正则 + 示例排除 + 安全检查（推荐） |
| **deep** | 完整扫描 + 低风险检测（最全面） |

## 风险等级

- 🔴 **HIGH**: 高风险，必须人工审查（eval, 数据外泄, 凭证窃取, 系统文件删除等）
- 🟡 **MEDIUM**: 中风险，建议审查（网络请求, 文件操作, API 调用等）
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

## 安全检查清单

TrustSkill 会检查以下内容：

### 敏感文件访问
- [ ] ~/.ssh/ 目录（SSH 密钥）
- [ ] ~/.openclaw/config.json（OpenClaw 配置）
- [ ] MEMORY.md, SOUL.md, USER.md（记忆文件）
- [ ] ~/.bashrc, ~/.zshrc（Shell 配置）
- [ ] .env 文件（环境变量）

### 凭证和密钥
- [ ] password, token, secret 关键词
- [ ] API Key 使用
- [ ] 硬编码的密钥

### 网络行为
- [ ] 外部 HTTP 请求
- [ ] 可疑域名（Pastebin, IP 直连）
- [ ] 数据外泄模式

### 系统操作
- [ ] 命令注入（eval, exec）
- [ ] 文件删除（rm -rf, shutil.rmtree）
- [ ] 系统文件访问

## 安全建议

1. **安装新 skill 前必扫描** - 特别是来自非官方渠道的 skill
2. **定期审计** - 对重要 skills 定期重新扫描
3. **关注 HIGH 风险** - 出现 HIGH 风险时必须人工确认
4. **不要完全依赖自动化** - 这是辅助工具，最终判断需要人

## 版本历史

- **v1.1.0** - 增强安全检测：凭证窃取、隐私文件访问、AI 服务 API 检测
- **v1.0.0** - 初始版本：基础安全风险检测

## License

MIT License
