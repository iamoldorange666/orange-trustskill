"""
扫描规则和配置
"""

from typing import List, Tuple, Dict, Any

# 高风险模式 - 恶意代码检测
HIGH_RISK_PATTERNS = {
    'command_injection': [
        (r'eval\s*\(', 'eval() execution'),
        (r'exec\s*\([^)]*[\+\%\$\{\}]', 'exec() with variable'),
        (r'os\.system\s*\([^)]*[\+\%\$\{\}]', 'os.system with variable'),
        (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'subprocess with shell=True'),
        (r'compile\s*\([^)]*[\+\%\$\{\}]', 'compile() with variable'),
    ],
    'data_exfiltration': [
        (r'requests\.(post|put)\s*\([^)]*http', 'HTTP POST to external server'),
        (r'urllib\.(request|urlopen)', 'urllib network request'),
        (r'http\.client', 'HTTP client usage'),
        (r'socket\.(socket|connect)', 'Socket network connection'),
    ],
    'file_deletion': [
        (r'shutil\.rmtree\s*\([^)]*[\/\*]', 'Recursive directory deletion'),
        (r'os\.remove\s*\([^)]*\*', 'Wildcard file deletion'),
        (r'rm\s+-rf', 'rm -rf command'),
        (r'os\.unlink\s*\([^)]*\*', 'Wildcard file unlink'),
    ],
    'credential_access': [
        (r'open\s*\([^)]*\.ssh[/\\]', 'SSH key access'),
        (r'open\s*\([^)]*password', 'Password file access'),
        (r'open\s*\([^)]*token', 'Token file access'),
        (r'open\s*\([^)]*secret', 'Secret file access'),
        (r'open\s*\([^)]*api[_-]?key', 'API key file access'),
    ],
    'sensitive_file_access': [
        (r'\.openclaw[/\\]config\.json', 'OpenClaw config access'),
        (r'\.bashrc|\.zshrc|\.profile|\.bash_profile', 'Shell config access'),
        (r'~/.ssh/', 'SSH directory access'),
    ],
    'memory_file_access': [
        (r'open\s*\([^)]*AGENTS\.md', 'AGENTS.md access - contains behavior rules'),
        (r'open\s*\([^)]*SOUL\.md', 'SOUL.md access - contains personality'),
        (r'open\s*\([^)]*USER\.md', 'USER.md access - contains user info'),
        (r'open\s*\([^)]*MEMORY\.md', 'MEMORY.md access - contains long-term memory'),
        (r'AGENTS\.md|SOUL\.md|USER\.md|MEMORY\.md', 'Memory file reference detected'),
    ],
}

# 中风险模式 - 需要审查
MEDIUM_RISK_PATTERNS = {
    'network_request': [
        (r'requests\.(get|post|put|delete)', 'HTTP request'),
        (r'urllib', 'urllib usage'),
        (r'httpx', 'httpx usage'),
        (r'aiohttp', 'aiohttp usage'),
    ],
    'file_access_outside_workspace': [
        (r'open\s*\([^)]*[\'"]\s*/etc/', 'System file access (/etc)'),
        (r'open\s*\([^)]*[\'"]\s*/sys/', 'System file access (/sys)'),
        (r'expanduser\s*\(\s*[\'"]~[\'"]', 'Home directory access'),
        (r'Path\.home\(\)', 'Home directory access'),
    ],
    'obfuscation': [
        (r'base64\.(b64decode|decode)', 'Base64 decoding'),
        (r'codecs\.decode', 'Codec decoding'),
        (r'\.decode\s*\([^)]*rot13', 'ROT13 decoding'),
        (r'zlib\.(decompress|compress)', 'zlib compression'),
        (r'gzip\.', 'gzip compression'),
    ],
    'dynamic_import': [
        (r'__import__\s*\(', 'Dynamic import'),
        (r'importlib\.(import_module|__import__)', 'Dynamic import'),
        (r'exec\s*\(', 'exec() call'),
        (r'compile\s*\(', 'compile() call'),
    ],
    'api_key_usage': [
        (r'api[_-]?key\s*=', 'API key assignment'),
        (r'gemini|openai|anthropic|claude', 'AI service API'),
        (r'api[_-]?secret', 'API secret usage'),
        (r'auth[_-]?token', 'Auth token usage'),
    ],
    'environment_access': [
        (r'os\.environ', 'Environment variable access'),
        (r'os\.getenv', 'getenv call'),
        (r'dotenv', 'dotenv usage'),
    ]
}

# 低风险模式 - 信息提示
LOW_RISK_PATTERNS = {
    'shell_command': [
        (r'os\.system\s*\(', 'os.system call'),
        (r'subprocess\.', 'Subprocess usage'),
        (r'os\.popen', 'os.popen call'),
    ],
    'file_operation': [
        (r'open\s*\(', 'File open'),
        (r'os\.path\.', 'Path manipulation'),
        (r'pathlib', 'Pathlib usage'),
        (r'shutil\.', 'shutil usage'),
    ],
    'json_parsing': [
        (r'json\.loads', 'JSON parsing'),
        (r'json\.load', 'JSON file loading'),
    ],
    'yaml_parsing': [
        (r'yaml\.', 'YAML parsing'),
        (r'pyyaml', 'PyYAML usage'),
    ]
}

# 可疑 URL/IP 模式
SUSPICIOUS_PATTERNS = [
    (r'http://[^/\s]*\d+\.\d+\.\d+\.\d+', 'Direct IP access (HTTP)'),
    (r'https?://[^/\s]*pastebin', 'Pastebin URL'),
    (r'https?://[^/\s]*githubusercontent', 'Raw GitHub content'),
    (r'https?://[^/\s]*ngrok', 'Ngrok tunnel'),
    (r'https?://[^/\s]*serveo', 'Serveo tunnel'),
    (r'https?://[^/\s]*localhost\.run', 'Localtunnel'),
]

# 安全服务白名单
SAFE_SERVICES = [
    'api.nvidia.com',
    'integrate.api.nvidia.com',
    'api.openai.com',
    'generativelanguage.googleapis.com',
    'api.anthropic.com',
    'api.xiaohongshu.com',
    'xiaohongshu.com',
    'api.github.com',
    'raw.githubusercontent.com',
    'pypi.org',
    'files.pythonhosted.org',
]

# 文件扩展名扫描列表
SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.sh', '.bash', '.zsh', '.fish',
    '.rb', '.pl', '.php', '.go', '.rs', '.java', '.c', '.cpp',
    '.md', '.txt', '.json', '.yaml', '.yml', '.toml'
}

# 忽略的文件/目录
IGNORE_PATTERNS = [
    r'\.git',
    r'\.svn',
    r'\.hg',
    r'node_modules',
    r'__pycache__',
    r'\.pytest_cache',
    r'\.venv',
    r'venv',
    r'\.env',
    r'dist',
    r'build',
    r'\.egg-info',
    r'\.tox',
    r'\.coverage',
]
