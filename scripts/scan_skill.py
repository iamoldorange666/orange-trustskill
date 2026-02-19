#!/usr/bin/env python3
"""
Skill Security Scanner for OpenClaw - Enhanced Version
Detects malicious code, backdoors, credential theft, and security risks
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set


class SecurityScanner:
    """Enhanced security scanner for OpenClaw skills"""
    
    # High risk patterns - potentially malicious
    HIGH_RISK_PATTERNS = {
        'command_injection': [
            (r'eval\s*\(', 'eval() execution'),
            (r'exec\s*\([^)]*[\+\%\$\{\}]', 'exec() with variable'),
            (r'os\.system\s*\([^)]*[\+\%\$\{\}]', 'os.system with variable'),
            (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'subprocess with shell=True'),
        ],
        'data_exfiltration': [
            (r'requests\.(post|put)\s*\([^)]*http', 'HTTP POST to external server'),
            (r'urllib\.(request|urlopen)', 'urllib network request'),
            (r'http\.client', 'HTTP client usage'),
        ],
        'file_deletion': [
            (r'shutil\.rmtree\s*\([^)]*[\/\*]', 'Recursive directory deletion'),
            (r'os\.remove\s*\([^)]*\*', 'Wildcard file deletion'),
            (r'rm\s+-rf', 'rm -rf command'),
        ],
        'credential_access': [
            (r'open\s*\([^)]*\.ssh[/\\]', 'SSH key access'),
            (r'open\s*\([^)]*password', 'Password file access'),
            (r'open\s*\([^)]*token', 'Token file access'),
            (r'open\s*\([^)]*secret', 'Secret file access'),
        ],
        'sensitive_file_access': [
            (r'\.openclaw[/\\]config\.json', 'OpenClaw config access'),
            (r'MEMORY\.md|SOUL\.md|USER\.md|AGENTS\.md', 'Memory file access'),
            (r'\.bashrc|\.zshrc|\.profile', 'Shell config access'),
            (r'\.env[^/]*', 'Environment file access'),
        ]
    }
    
    # Medium risk patterns - needs review
    MEDIUM_RISK_PATTERNS = {
        'network_request': [
            (r'requests\.(get|post|put|delete)', 'HTTP request'),
            (r'urllib', 'urllib usage'),
        ],
        'file_access_outside_workspace': [
            (r'open\s*\([^)]*[\'"]\s*[/\\]etc[/\\]', 'System file access'),
            (r'open\s*\([^)]*[\'"]\s*[/\\]sys', 'System file access'),
            (r'expanduser\s*\(\s*[\'"]~[\'"]', 'Home directory access'),
        ],
        'obfuscation': [
            (r'base64\.(b64decode|decode)', 'Base64 decoding'),
            (r'codecs\.decode', 'Codec decoding'),
            (r'\.decode\s*\([^)]*rot13', 'ROT13 decoding'),
        ],
        'dynamic_import': [
            (r'__import__\s*\(', 'Dynamic import'),
            (r'importlib\.(import_module|__import__)', 'Dynamic import'),
        ],
        'api_key_usage': [
            (r'api[_-]?key|apikey', 'API key usage'),
            (r'gemini|openai|anthropic', 'AI service API call'),
        ]
    }
    
    # Low risk patterns - informational
    LOW_RISK_PATTERNS = {
        'shell_command': [
            (r'os\.system\s*\(', 'os.system call'),
            (r'subprocess\.', 'Subprocess usage'),
        ],
        'file_operation': [
            (r'open\s*\(', 'File open'),
            (r'os\.path\.', 'Path manipulation'),
        ],
    }
    
    # Suspicious domains/IPs
    SUSPICIOUS_PATTERNS = [
        (r'http://[^/\s]*\d+\.\d+\.\d+\.\d+', 'Direct IP access (HTTP)'),
        (r'https?://[^/\s]*pastebin', 'Pastebin URL'),
        (r'https?://[^/\s]*githubusercontent', 'Raw GitHub content'),
    ]
    
    # Safe external services (expected for certain skills)
    SAFE_SERVICES = [
        'api.nvidia.com',
        'api.openai.com',
        'generativelanguage.googleapis.com',
        'api.anthropic.com',
        'api.xiaohongshu.com',
        'xiaohongshu.com',
    ]
    
    def __init__(self, skill_path: str, mode: str = 'standard'):
        self.skill_path = Path(skill_path)
        self.mode = mode
        self.findings = []
        self.checked_files: Set[Path] = set()
        
    def scan(self) -> Dict[str, Any]:
        """Run full security scan"""
        if not self.skill_path.exists():
            return {'error': f'Skill path not found: {self.skill_path}'}
        
        files_to_scan = self._get_files_to_scan()
        
        for file_path in files_to_scan:
            if file_path not in self.checked_files:
                self._scan_file(file_path)
                self.checked_files.add(file_path)
        
        return {
            'skill_path': str(self.skill_path),
            'files_scanned': len(self.checked_files),
            'findings': self.findings,
            'risk_summary': self._get_risk_summary(),
            'security_assessment': self._generate_assessment()
        }
    
    def _get_files_to_scan(self) -> List[Path]:
        """Get list of files to scan"""
        files = []
        extensions = {'.py', '.js', '.sh', '.bash', '.zsh', '.md', '.txt'}
        
        for ext in extensions:
            files.extend(self.skill_path.rglob(f'*{ext}'))
        
        # Check SKILL.md
        skill_md = self.skill_path / 'SKILL.md'
        if skill_md.exists():
            files.append(skill_md)
            
        return list(set(files))  # Remove duplicates
    
    def _is_in_string_literal(self, content: str, position: int) -> bool:
        """Check if position is inside a string literal"""
        lines_before = content[:position].split('\n')
        current_line = lines_before[-1] if lines_before else ""
        
        single_quotes = current_line.count("'") - current_line.count("\'")
        double_quotes = current_line.count('"') - current_line.count('\"')
        
        return (single_quotes % 2 == 1 or double_quotes % 2 == 1)
    
    def _is_pattern_definition(self, content: str, position: int) -> bool:
        """Check if the match is part of a regex pattern definition"""
        context = content[max(0, position-100):position+100]
        pattern_indicators = [
            "PATTERNS", "patterns", "regex", "PATTERN", 
            "r'", 'r"', "re.compile", ".compile("
        ]
        return any(indicator in context for indicator in pattern_indicators)
    
    def _is_example_code(self, content: str, position: int) -> bool:
        """Check if the match is in example/comment context"""
        start = max(0, position - 200)
        end = min(len(content), position + 200)
        context = content[start:end].lower()
        
        example_indicators = [
            'example', 'danger:', 'caution:', 'warning:', 
            'bad:', 'wrong:', 'unsafe:', 'risk:', 'pattern', 'todo:'
        ]
        return any(indicator in context for indicator in example_indicators)
    
    def _is_safe_service(self, url: str) -> bool:
        """Check if URL is a known safe service"""
        return any(service in url for service in self.SAFE_SERVICES)
    
    def _scan_file(self, file_path: Path):
        """Scan a single file"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            relative_path = file_path.relative_to(self.skill_path)
        except Exception:
            return
        
        is_reference = 'reference' in str(file_path).lower() or str(file_path).endswith('_patterns.md')
        
        # Check high risk patterns
        for category, patterns in self.HIGH_RISK_PATTERNS.items():
            for pattern, description in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    if (is_reference or 
                        self._is_example_code(content, match.start()) or
                        self._is_in_string_literal(content, match.start()) or
                        self._is_pattern_definition(content, match.start())):
                        continue
                    
                    line_num = content[:match.start()].count('\n') + 1
                    snippet = self._get_snippet(content, match.start())
                    
                    self.findings.append({
                        'level': 'HIGH',
                        'category': category,
                        'description': description,
                        'file': str(relative_path),
                        'line': line_num,
                        'snippet': snippet
                    })
        
        # Check medium risk patterns
        if self.mode in ['standard', 'deep']:
            for category, patterns in self.MEDIUM_RISK_PATTERNS.items():
                for pattern, description in patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[:match.start()].count('\n') + 1
                        self.findings.append({
                            'level': 'MEDIUM',
                            'category': category,
                            'description': description,
                            'file': str(relative_path),
                            'line': line_num,
                            'snippet': self._get_snippet(content, match.start())
                        })
        
        # Check low risk patterns
        if self.mode == 'deep':
            for category, patterns in self.LOW_RISK_PATTERNS.items():
                for pattern, description in patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[:match.start()].count('\n') + 1
                        self.findings.append({
                            'level': 'LOW',
                            'category': category,
                            'description': description,
                            'file': str(relative_path),
                            'line': line_num,
                            'snippet': self._get_snippet(content, match.start())
                        })
        
        # Check suspicious URLs
        for pattern, description in self.SUSPICIOUS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                url = match.group(0)
                if self._is_safe_service(url):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                self.findings.append({
                    'level': 'MEDIUM',
                    'category': 'suspicious_url',
                    'description': description,
                    'file': str(relative_path),
                    'line': line_num,
                    'snippet': self._get_snippet(content, match.start())
                })
    
    def _get_snippet(self, content: str, position: int, context: int = 50) -> str:
        """Get code snippet around position"""
        start = max(0, position - context)
        end = min(len(content), position + context)
        snippet = content[start:end].replace('\n', ' ').strip()
        return snippet[:100] + '...' if len(snippet) > 100 else snippet
    
    def _get_risk_summary(self) -> Dict[str, int]:
        """Get summary of risk levels"""
        summary = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            summary[finding['level']] += 1
        return summary
    
    def _generate_assessment(self) -> str:
        """Generate overall security assessment"""
        summary = self._get_risk_summary()
        
        if summary['HIGH'] > 0:
            return "CRITICAL: High-risk issues detected. Manual review required before execution."
        elif summary['MEDIUM'] > 5:
            return "WARNING: Multiple medium-risk issues found. Review recommended."
        elif summary['MEDIUM'] > 0:
            return "CAUTION: Some medium-risk issues found. Review suggested."
        else:
            return "SAFE: No significant security issues found."
    
    def export_for_llm(self) -> str:
        """Export findings for LLM review"""
        lines = [
            "=" * 60,
            "SKILL SECURITY SCAN - LLM REVIEW EXPORT",
            "=" * 60,
            f"\nSkill Path: {self.skill_path}",
            f"Scan Mode: {self.mode}",
            f"Total Findings: {len(self.findings)}\n"
        ]
        
        for finding in self.findings:
            lines.extend([
                f"\n[{finding['level']}] {finding['category']}",
                f"File: {finding['file']}:{finding['line']}",
                f"Issue: {finding['description']}",
                f"Code: {finding['snippet']}",
                "-" * 40
            ])
        
        return '\n'.join(lines)


def print_report(result: Dict[str, Any], format_type: str = 'text'):
    """Print scan report"""
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    if format_type == 'json':
        print(json.dumps(result, indent=2))
        return
    
    # Text format
    print("=" * 60)
    print("SKILL SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"\nSkill: {result['skill_path']}")
    print(f"Files Scanned: {result['files_scanned']}")
    print(f"Total Findings: {len(result['findings'])}")
    
    summary = result['risk_summary']
    print(f"\n📊 Risk Summary:")
    print(f"  🔴 HIGH:   {summary['HIGH']}")
    print(f"  🟡 MEDIUM: {summary['MEDIUM']}")
    print(f"  🟢 LOW:    {summary['LOW']}")
    
    if result['findings']:
        print(f"\n{'='*60}")
        print("DETAILED FINDINGS")
        print(f"{'='*60}")
        
        for finding in result['findings']:
            level_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}[finding['level']]
            print(f"\n{level_icon} [{finding['level']}] {finding['category']}")
            print(f"   File: {finding['file']}:{finding['line']}")
            print(f"   Issue: {finding['description']}")
            print(f"   Code: {finding['snippet']}")
    else:
        print("\n✅ No security issues found!")
    
    print(f"\n{'='*60}")
    print(f"Assessment: {result.get('security_assessment', 'N/A')}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='Orange TrustSkill - Security scanner for OpenClaw skills'
    )
    parser.add_argument('skill_path', help='Path to skill directory')
    parser.add_argument(
        '--mode', 
        choices=['fast', 'standard', 'deep'],
        default='standard',
        help='Scanning mode (default: standard)'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format'
    )
    parser.add_argument(
        '--export-for-llm',
        action='store_true',
        help='Export findings for LLM review'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Quiet mode (only show issue count)'
    )
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(args.skill_path, args.mode)
    result = scanner.scan()
    
    if args.export_for_llm:
        print(scanner.export_for_llm())
    elif args.quiet:
        summary = result.get('risk_summary', {})
        print(f"HIGH:{summary.get('HIGH',0)} MEDIUM:{summary.get('MEDIUM',0)} LOW:{summary.get('LOW',0)}")
    else:
        print_report(result, args.format)
    
    # Exit with error code if high risk issues found
    if result.get('risk_summary', {}).get('HIGH', 0) > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
