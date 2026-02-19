#!/usr/bin/env python3
"""
Skill Security Scanner for OpenClaw
Detects malicious code, backdoors, and security risks in skills
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple


class SecurityScanner:
    """Security scanner for OpenClaw skills"""
    
    # High risk patterns
    HIGH_RISK_PATTERNS = {
        'command_injection': [
            (r'eval\s*\(', 'eval() execution'),
            (r'exec\s*\([^)]*\+', 'exec() with variable'),
            (r'os\.system\s*\([^)]*[\+\%\$\{]', 'os.system with variable'),
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
        ]
    }
    
    # Medium risk patterns
    MEDIUM_RISK_PATTERNS = {
        'network_request': [
            (r'requests\.(get|post|put|delete)', 'HTTP request'),
            (r'urllib', 'urllib usage'),
        ],
        'file_access': [
            (r'open\s*\([^)]*[\'"]\s*[/\\]etc[/\\]', 'System file access'),
            (r'open\s*\([^)]*[\'"]\s*[/\\]sys', 'System file access'),
        ],
        'obfuscation': [
            (r'base64\.(b64decode|decode)', 'Base64 decoding'),
            (r'codecs\.decode', 'Codec decoding'),
            (r'\.decode\s*\([^)]*rot13', 'ROT13 decoding'),
        ],
        'dynamic_import': [
            (r'__import__\s*\(', 'Dynamic import'),
            (r'importlib\.(import_module|__import__)', 'Dynamic import'),
        ]
    }
    
    # Low risk patterns
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
    
    def __init__(self, skill_path: str, mode: str = 'standard'):
        self.skill_path = Path(skill_path)
        self.mode = mode
        self.findings = []
        
    def scan(self) -> Dict[str, Any]:
        """Run full security scan"""
        if not self.skill_path.exists():
            return {'error': f'Skill path not found: {self.skill_path}'}
        
        # Find all relevant files
        files_to_scan = self._get_files_to_scan()
        
        for file_path in files_to_scan:
            self._scan_file(file_path)
        
        return {
            'skill_path': str(self.skill_path),
            'files_scanned': len(files_to_scan),
            'findings': self.findings,
            'risk_summary': self._get_risk_summary()
        }
    
    def _get_files_to_scan(self) -> List[Path]:
        """Get list of files to scan"""
        files = []
        extensions = {'.py', '.js', '.sh', '.bash', '.zsh', '.md'}
        
        for ext in extensions:
            files.extend(self.skill_path.rglob(f'*{ext}'))
        
        # Also check SKILL.md
        skill_md = self.skill_path / 'SKILL.md'
        if skill_md.exists() and skill_md not in files:
            files.append(skill_md)
        
        return files
    
    def _is_in_string_literal(self, content: str, position: int) -> bool:
        """Check if position is inside a string literal (likely a regex pattern)"""
        # Look backwards to find if we're inside quotes
        lines_before = content[:position].split('\n')
        current_line = lines_before[-1] if lines_before else ""
        
        # Count quotes in current line before position
        single_quotes = current_line.count("'") - current_line.count("\'")
        double_quotes = current_line.count('"') - current_line.count('\"')
        triple_single = current_line.count("'''")
        triple_double = current_line.count('"""')
        
        # Simple heuristic: odd number of quotes means we're inside a string
        in_string = (single_quotes % 2 == 1 or double_quotes % 2 == 1 or 
                     triple_single > 0 or triple_double > 0)
        return in_string
    
    def _is_pattern_definition(self, content: str, position: int) -> bool:
        """Check if the match is part of a regex pattern definition"""
        # Check if it's in a list of patterns
        context = content[max(0, position-100):position+100]
        pattern_indicators = [
            "PATTERNS", "patterns", "regex", "PATTERN", 
            r"r'", r'r"', "re.compile", ".compile("
        ]
        return any(indicator in context for indicator in pattern_indicators)
    
    def _is_example_code(self, content: str, position: int) -> bool:
        """Check if the match is in example/comment context"""
        # Get surrounding context
        start = max(0, position - 200)
        end = min(len(content), position + 200)
        context = content[start:end].lower()
        
        # Check for example indicators
        example_indicators = [
            'example', 'danger:', 'caution:', 'warning:', 
            'bad:', 'wrong:', 'unsafe:', 'risk:', 'pattern'
        ]
        return any(indicator in context for indicator in example_indicators)
    
    def _scan_file(self, file_path: Path):
        """Scan a single file"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            relative_path = file_path.relative_to(self.skill_path)
        except Exception as e:
            return
        
        # Skip scanning reference files for actual malicious patterns
        # (they contain examples of malicious code)
        is_reference_file = 'reference' in str(file_path).lower() or str(file_path).endswith('_patterns.md')
        
        # Check high risk patterns
        for category, patterns in self.HIGH_RISK_PATTERNS.items():
            for pattern, description in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Skip if in example/documentation context or pattern definition
                    if (is_reference_file or 
                        self._is_example_code(content, match.start()) or
                        self._is_in_string_literal(content, match.start()) or
                        self._is_pattern_definition(content, match.start())):
                        continue
                    line_num = content[:match.start()].count('\n') + 1
                    self.findings.append({
                        'level': 'HIGH',
                        'category': category,
                        'description': description,
                        'file': str(relative_path),
                        'line': line_num,
                        'snippet': self._get_snippet(content, match.start())
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
    
    def export_for_llm(self) -> str:
        """Export findings for LLM review"""
        report = []
        report.append("=" * 60)
        report.append("SKILL SECURITY SCAN - LLM REVIEW EXPORT")
        report.append("=" * 60)
        report.append(f"\nSkill Path: {self.skill_path}")
        report.append(f"Scan Mode: {self.mode}")
        report.append(f"Total Findings: {len(self.findings)}\n")
        
        for finding in self.findings:
            report.append(f"\n[{finding['level']}] {finding['category']}")
            report.append(f"File: {finding['file']}:{finding['line']}")
            report.append(f"Issue: {finding['description']}")
            report.append(f"Code: {finding['snippet']}")
            report.append("-" * 40)
        
        return '\n'.join(report)


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
    print(f"\nRisk Summary:")
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
    
    # Recommendations
    if summary['HIGH'] > 0:
        print("⚠️  CRITICAL: High-risk issues detected. Manual review required before execution.")
    elif summary['MEDIUM'] > 0:
        print("⚡ WARNING: Medium-risk issues found. Review recommended before execution.")
    else:
        print("✓ Scan complete. Skill appears safe for execution.")


def main():
    parser = argparse.ArgumentParser(
        description='Security scanner for OpenClaw skills'
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
