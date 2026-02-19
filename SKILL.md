---
name: orange-trustskill
description: Orange's TrustSkill - Security scanner for OpenClaw skills. Detects malicious code, backdoors, command injection, file system risks, network exfiltration, and sensitive data leaks in skill scripts. Use when: (1) Installing a new skill from untrusted source, (2) Auditing existing skills for security, (3) Before executing skill code that performs system operations, (4) Validating skills before publishing to ClawHub.
---

# Skill Security Scanner

A security scanner for OpenClaw skills that detects potential malicious code, backdoors, and security risks.

## Quick Start

Scan a skill directory:
```bash
python scripts/scan_skill.py /path/to/skill-folder
```

## Scanning Modes

- **fast**: Pattern matching only (quickest)
- **standard**: Pattern matching + AST analysis (default, recommended)
- **deep**: Pattern matching + AST + LLM review (most thorough)

## Usage Examples

### Basic scan
```bash
python scripts/scan_skill.py ~/.openclaw/skills/some-skill
```

### Deep scan with JSON output
```bash
python scripts/scan_skill.py ~/.openclaw/skills/some-skill --mode deep --format json
```

### Export for manual LLM review
```bash
python scripts/scan_skill.py ~/.openclaw/skills/some-skill --export-for-llm
```

## What It Detects

### High Risk
- Command injection (`eval`, `exec`, `os.system` with variables)
- Network exfiltration (suspicious HTTP requests, data uploading)
- File system deletion (`rm -rf`, `shutil.rmtree` on system paths)
- Credential harvesting (password/key extraction)

### Medium Risk
- File system operations outside workspace
- Network requests to unknown domains
- Code obfuscation (base64, hex encoding)
- Dynamic code execution

### Low Risk
- Shell command execution (with static commands)
- File read operations
- Environment variable access

## When to Use This Skill

1. **Before installing untrusted skills** - Always scan skills from unknown sources
2. **Periodic audits** - Regular security checks of installed skills
3. **Pre-execution validation** - Before running skill scripts that modify system
4. **Publishing validation** - Before publishing skills to ClawHub

## Security Patterns

See [security_patterns.md](references/security_patterns.md) for detailed patterns and detection rules.

## Response to Findings

### Critical (Stop immediately)
- Confirmed backdoor or data exfiltration
- System-level destructive operations

### High Risk (Manual review required)
- Suspicious network requests
- Command injection patterns
- Report to user and await confirmation

### Medium/Low Risk (Proceed with caution)
- Document findings
- Inform user of potential risks
- Proceed if user confirms
